import logging

logger = logging.getLogger("NetworkAutomator")

def analyze(host: str, output: str) -> list[str]:
    """В данном случае ждет вывода конфигурации show run или show run | i user,
        и если там имеется юзер test, добавляет в команды хоста, команду на его удаление"""
    commands = []
    if "username test" in output:
        logger.info(f"Analysis: Found 'username test' on {host}. Adding to fix-list.")
        commands.append("no username test")

    return commands
