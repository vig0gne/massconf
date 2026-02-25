#!/usr/bin/env python
###
### Для работы необходимы два файла в каталоге запуска скрипта:
### hosts.txt - список хостов (fqdn или ip). Последняя строка должна быть пустой.
### commands.txt - список команд, выполняемых на каждом из хостов.
###
### По результатам формируется два файла в каталоге запуска скрипта:
### messages.log - лог выполнения задач
### failed.txt - список хостов, где была ошибка.
###


from scrapli.driver.core import IOSXEDriver, NXOSDriver
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliTimeout, ScrapliException
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
import logging
import sys
import os
import importlib
from dotenv import load_dotenv, find_dotenv


# Пробуем заимпортить настройки, если их нет, то включим умолчания
try:
    from settings import *
except ImportError:
    DRIVERS = [IOSXEDriver, NXOSDriver]
    COMMANDS_FILE = os.path.abspath('commands.txt')
    HOSTS_FILE = os.path.abspath('hosts.txt')
    LOG_FILE = os.path.abspath('messages.log')
    FAILED_FILE = os.path.abspath('failed.txt')
    SSH_CONFIG_FILE = os.path.abspath("ssh_config")
    THREADS = 30
    SCRAPLI_TRANSPORT = "system"
    TIMEOUT_OPS = 60
    TIMEOUT_SOCKET = 20
    TIMEOUT_TRANSPORT = 30
    PRIV_CMDS = ("show", "wr", "ping", "traceroute", "clear")
    SCRAPLI_DEBUG = False
    ANALYZER_MODULE = ""

load_dotenv(find_dotenv())

# Настройка логирования
logger = logging.getLogger("NetworkAutomator")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('[%(asctime)s]:[%(levelname)s]: %(message)s')

# Консоль
stdouthandler = logging.StreamHandler(sys.stdout)
stdouthandler.setFormatter(formatter)
logger.addHandler(stdouthandler)

# Файл лога
filehandler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
filehandler.setFormatter(formatter)
logger.addHandler(filehandler)

# Отдельный логгер для неудачных попыток (чтобы не писать в файл вручную через open)
failed_logger = logging.getLogger("FailedHosts")
failed_logger.addHandler(logging.FileHandler(FAILED_FILE, mode='a'))

# Настройка дебага scrapli. Если не нужен, изменить значение переменной DEBUG_LOG на False
if SCRAPLI_DEBUG:
    # Создаем логгер для самой библиотеки scrapli
    scrapli_logger = logging.getLogger("scrapli")
    scrapli_logger.setLevel(logging.DEBUG) # Самый детальный уровень

    # Записываем сырые данные SSH в отдельный файл, чтобы не засорять основной лог
    scrapli_file = logging.FileHandler("scrapli_debug.log", mode='w', encoding='utf-8')
    scrapli_file.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    scrapli_logger.addHandler(scrapli_file)


def execute_logic(conn, commands_to_run: list[str]) -> tuple[str, bool]:
    """Внутренняя логика выполнения команд на открытом соединении"""
    full_result = ""
    config_changed = False
    for cmd in commands_to_run:
        if not cmd.strip():
            continue

        # Интерактив: no username
        if cmd.startswith("no username"):
            conn.acquire_priv("configuration")
            prompt = conn.get_prompt()
            res = conn.send_interactive([(cmd, "[confirm]")],
                                        privilege_level="configuration",
                                        interaction_complete_patterns=[prompt]
                                        ).result
            full_result += f"{res}\n"
            config_changed = True

        # Интерактив: copy
        elif cmd.startswith("copy"):
            res = conn.send_interactive([
                (cmd, "Destination filename"),
                ("\n", "[confirm]")
            ]).result
            full_result += f"{res}\n"

        # Обычные команды show/wr
        elif cmd.startswith(PRIV_CMDS):
            res = conn.send_command(cmd).result
            full_result += f"{res}\n"

        # Конфигурационные команды
        else:
            res = conn.send_config(cmd,
                                   strip_prompt=False,
                                    privilege_level="configuration").result
            full_result += f"{cmd}\n{res}\n"
            config_changed = True

    return full_result, config_changed


def load_analyzer(module_name: str):
    """
    Динамическая загрузка пользовательского модуля аналитики.
    Ожидается функция analyze(host, output)
    """
    try:
        module = importlib.import_module(f"analyzer_modules.{module_name}")

        if not hasattr(module, "analyze"):
            raise AttributeError(
                f"Module {module_name} has no 'analyze(host, output)' function"
            )

        logger.info(f"Loaded analyzer module: {module_name}")
        return module.analyze

    except Exception as e:
        logger.warning(f"Analyzer load failed: {e}")
        return lambda conn, host, output: []


class DeviceManager:
    def __init__(self, device_dict: dict[str, Any], commands: list[str]):
        self.device_dict = device_dict
        self.commands = commands
        self.host = device_dict.get('host')
        self.analyze = ANALYZER_MODULE
        if self.analyze:
            self.analyzer = load_analyzer(self.analyze)
        else:
            self.analyzer = lambda host, output: []

    def _prepare_session(self, conn, driver_class):
        """
        Выполняется один раз после подключения.
        Отключает пагинацию в зависимости от платформы.
        """
        driver_name = driver_class.__name__

        try:
            if driver_name == "ASADriver":
                conn.send_command("terminal pager 0")
            else:
                # IOS / IOS-XE / NX-OS
                conn.send_command("terminal length 0")
                # Для NX-OS дополнительно
                conn.send_command("terminal width 511")
                # Удостоверяемся, что мы в привилегированном режиме
                conn.acquire_priv("privilege_exec")

        except Exception as e:
            logger.debug(f"{self.host}: session preparation failed: {e}")

    def _save_config(self, conn, driver_class):
        try:
            driver_name = driver_class.__name__

            if driver_name == "NXOSDriver":
                conn.send_command("copy running-config startup-config")
            elif driver_name == "ASADriver":
                conn.send_command("write memory")
            else:
                conn.send_command("write memory")

            logger.info(f"{self.host}: Configuration saved")

        except Exception as e:
            logger.warning(f"{self.host}: Failed to save config: {e}")

    def run(self):
        """Попытка подключения с перебором драйверов"""
        last_error = "Unknown Error"

        for driver_class in DRIVERS:
            try:
                # Используем контекстный менеджер для каждого драйвера
                with driver_class(**self.device_dict) as conn:
                    logger.info(f"Connected to {self.host} using {driver_class.__name__}")
                    self._prepare_session(conn, driver_class)
                    output, config_changed = execute_logic(conn, self.commands)
                    if self.analyze:
                        fix_commands = self.analyzer(self.host, output)
                        if fix_commands:
                            logger.info(f"{self.host}: Analyzer generated {len(fix_commands)} commands")
                            fix_output, fix_changed = execute_logic(conn, fix_commands)
                            output += "\n--- ANALYZER FIX ---\n" + fix_output
                            config_changed = config_changed or fix_changed

                    logger.info(f"SUCCESS: {self.host}\n{output}")
                    if config_changed:
                        self._save_config(conn, driver_class)
                    return

            except ScrapliAuthenticationFailed:
                last_error = "Authentication Failed"
                break  # Если пароль неверный, менять драйвер смысла нет
            except ScrapliTimeout:
                last_error = "Timeout (Check connectivity or Driver/Prompt)"
                continue  # Пробуем следующий драйвер
            except ScrapliException as e:
                last_error = f"Scrapli Error Type: {type(e).__name__}, Details: {str(e)}"
                continue
            except Exception as e:
                last_error = f"General Error: {str(e)}"
                break

        # Если дошли сюда, значит все драйверы не сработали
        logger.error(f"FAILED: {self.host} - {last_error}")
        failed_logger.error(self.host)


def get_devices(hostfile: str) -> list[dict[str, Any]]:
    login = os.getenv("LOGIN")
    password = os.getenv("PASSWORD")

    devices = []
    if not os.path.exists(hostfile):
        logger.error(f"File {hostfile} not found!")
        return []

    with open(hostfile, 'r') as f:
        devices = []
        for line in f:
            host = line.strip()
            if host:
                device_config = ({
                    "host": host,
                    "ssh_config_file": SSH_CONFIG_FILE,
                    "auth_username": login,
                    "auth_password": password,
                    "auth_strict_key": False,
                    "transport": SCRAPLI_TRANSPORT,
                    "timeout_ops": TIMEOUT_OPS,
                    "timeout_socket": TIMEOUT_SOCKET,
                    "timeout_transport": TIMEOUT_TRANSPORT
                })
                devices.append(device_config)
    return devices


def get_commands(cmdfile: str) -> list[str]:
    if not os.path.exists(cmdfile):
        return []
    with open(cmdfile, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def main():
    devices = get_devices(HOSTS_FILE)
    commands = get_commands(COMMANDS_FILE)

    if not devices or not commands:
        logger.error("No devices or commands to process. Exiting.")
        return

    logger.info(f"Starting job for {len(devices)} hosts with {THREADS} threads")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Создаем список задач
        futures = {executor.submit(DeviceManager(dev, commands).run): dev['host'] for dev in devices}

        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.critical(f"Unhandled exception for {host}: {e}")


if __name__ == '__main__':
    main()
