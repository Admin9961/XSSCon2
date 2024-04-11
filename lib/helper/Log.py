from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class Log:

    @classmethod
    def info(cls, text):
        print(f"[{Fore.YELLOW}{datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}] [{Fore.GREEN}INFO{Style.RESET_ALL}] {text}")

    @classmethod
    def warning(cls, text):
        print(f"[{Fore.YELLOW}{datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}] [{Fore.YELLOW}WARNING{Style.RESET_ALL}] {text}")

    @classmethod
    def high(cls, text):
        print(f"[{Fore.YELLOW}{datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}] [{Fore.RED}CRITICAL{Style.RESET_ALL}] {text}")
