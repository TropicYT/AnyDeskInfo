import os
import re
import sys
import time
import wmi
import psutil
import requests
import logging
from typing import List, Dict, Optional, Tuple
from colorama import init, Fore, Back, Style
from datetime import datetime


init()


file_logger = logging.getLogger('file_logger')
file_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("logip.log", mode='a', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
file_logger.addHandler(file_handler)


console_logger = logging.getLogger('console_logger')
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_logger.addHandler(console_handler)


IGNORED_PORTS = {80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 3306, 3389}


LOCAL_IP = re.compile(
    r'^('
    r'127\.0\.0\.1|'
    r'10\.(?:\d{1,3}\.){2}\d{1,3}|'
    r'192\.168\.(?:\d{1,3}\.)\d{1,3}|'
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.(?:\d{1,3}\.)\d{1,3}|'
    r'172\.17\.(?:\d{1,3}\.)\d{1,3}|'
    r'169\.254\.(?:\d{1,3}\.)\d{1,3}|'
    r'100\.(6[4-9]|7[0-9]|8[0-9]|9[0-9]|1[0-1][0-9]|12[0-7])\.(?:\d{1,3}\.)\d{1,3}|'
    r'192\.0\.2\.(?:\d{1,3})|'
    r'198\.18\.(?:\d{1,3}\.)\d{1,3}|'
    r'198\.51\.100\.(?:\d{1,3})|'
    r'203\.0\.113\.(?:\d{1,3})|'
    r'::1|'
    r'fc[0-9a-fA-F]{2}:'
    r'|fd[0-9a-fA-F]{2}:'
    r'|fe80:'
    r')'
)

def show_banner():
    banner = f"""
{Fore.RED}
/$$$$$$                        /$$   /$$ /$$ /$$ /$$
/$$__  $$                     | $$  /$$/|__/| $$| $$
| $$  \ $$ /$$$$$$$  /$$   /$$| $$ /$$/  /$$| $$| $$
| $$$$$$$$| $$__  $$| $$  | $$| $$$$$/  | $$| $$| $$
| $$__  $$| $$  \ $$| $$  | $$| $$  $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$\  $$ | $$| $$| $$
| $$  | $$| $$  | $$|  $$$$$$$| $$ \  $$| $$| $$| $$
|__/  |__/|__/  |__/ \____  $$|__/  \__/|__/|__/|__/
                     /$$  | $$                      
                    |  $$$$$$/                      
                     \______/                       
{Fore.YELLOW}
{'='*50}
{Fore.CYAN}Мониторинг подключений AnyDesk
{Fore.YELLOW}{'='*50}
{Fore.GREEN}Создатель: {Fore.MAGENTA}TROP1C
{Fore.YELLOW}{'='*50}
{Style.RESET_ALL}
"""
    print(banner)

def is_ip_in_logs(ip: str) -> bool:
    if not os.path.exists("logip.log"):
        return False
    with open("logip.log", "r", encoding='utf-8') as log_file:
        return any(f"IP: {ip}" in line for line in log_file)

def is_local_ip(ip: str) -> bool:
    return bool(LOCAL_IP.match(ip))

def get_ips() -> List[Dict[str, str]]:
    wmi_obj = wmi.WMI()
    connections = []

    for process in wmi_obj.Win32_Process():
        try:
            if 'anydesk' in process.Name.lower():
                for conn in psutil.Process(process.ProcessId).net_connections():
                    if conn.status in ('SYN_SENT', 'ESTABLISHED') and conn.raddr:
                        ip, port = conn.raddr.ip, conn.raddr.port
                        if port not in IGNORED_PORTS and not is_local_ip(ip):
                            if not any(c['IP'] == ip for c in connections):
                                connections.append({"IP": ip, "Port": str(port)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return connections

def get_anydesk_trace_info() -> Tuple[str, List[str]]:
    possible_paths = [
        os.path.join(os.getenv('APPDATA'), 'AnyDesk', 'connection_trace.txt'),
        os.path.join(os.getenv('ProgramData'), 'AnyDesk', 'connection_trace.txt'),
        os.path.join(os.getenv('ProgramFiles'), 'AnyDesk', 'connection_trace.txt'),
        os.path.join(os.getenv('ProgramFiles(x86)'), 'AnyDesk', 'connection_trace.txt'),
    ]
    
    trace_file_path = ""
    for path in possible_paths:
        if os.path.exists(path):
            trace_file_path = path
            break
    
    if not trace_file_path:
        return "Файл с логами не найден! Попросите кента отправить подключение!", []
    
    try:
        with open(trace_file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            return trace_file_path, lines[-3:] 
    except Exception as e:
        return f"Ошибка чтения файла: {str(e)}", []

def get_ip_info(ip_data: Dict[str, str]) -> Dict[str, str]:
    ip = ip_data['IP']
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "IP": ip,
            "Port": ip_data['Port'],
            "Страна": data.get('country', 'Неизвестно'),
            "Регион": data.get('regionName', 'Неизвестно'),
            "Город": data.get('city', 'Неизвестно'),
            "Провайдер": data.get('isp', 'Неизвестно'),
            "AS": data.get('as', 'Неизвестно')
        }
    except requests.exceptions.RequestException:
        return {**ip_data,
                "Страна": "Неизвестно",
                "Регион": "Неизвестно",
                "Город": "Неизвестно",
                "Провайдер": "Неизвестно",
                "AS": "Неизвестно"}

def save_connection_info(info: Dict[str, str], trace_info: Tuple[str, List[str]]) -> None:
    file_logger.info("="*40)
    file_logger.info("Обнаружено подключение!")
    file_logger.info("="*40)
    
    for key, value in info.items():
        file_logger.info(f'{key:<10}: {value}')

    file_logger.info("\nИнформация:")
    for line in trace_info[1]:
        file_logger.info(line)
    
    file_logger.info("="*40)
    file_handler.flush()

def main():
    show_banner()
    console_logger.info(f"{Fore.CYAN}Мониторинг подключений AnyDesk... [CTRL+C для выхода]{Style.RESET_ALL}")
    
    try:
        while True:
            connections = get_ips()
            
            if connections:
                console_logger.info(f"{Fore.YELLOW}Найдено {len(connections)} внешних подключений{Style.RESET_ALL}")
                for conn in connections:
                    if not is_ip_in_logs(conn['IP']):
                        console_logger.info(f"{Fore.RED}Новое подключение к: {conn['IP']}:{conn['Port']}{Style.RESET_ALL}")
                        

                        ip_info = get_ip_info(conn)
                        

                        trace_info = get_anydesk_trace_info()
                        

                        console_logger.info(f"{Fore.GREEN}Информация об IP:{Style.RESET_ALL}")
                        for key, value in ip_info.items():
                            console_logger.info(f"{Fore.CYAN}{key:<10}: {value}{Style.RESET_ALL}")
                        
                        console_logger.info(f"{Fore.MAGENTA}\nЕсть подключение! Айди ниже :3 (то что самое последнее цифры 1 столбец){Style.RESET_ALL}")
                        for line in trace_info[1]:
                            console_logger.info(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
                        

                        save_connection_info(ip_info, trace_info)
                        console_logger.info(f"{Fore.GREEN}Данные сохранены в лог-файл{Style.RESET_ALL}")
            else:
                console_logger.info(f"{Fore.GREEN}Внешние подключения не обнаружены{Style.RESET_ALL}")

            time.sleep(5)

    except KeyboardInterrupt:
        console_logger.info(f"\n{Fore.RED}Мониторинг остановлен{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == '__main__':
    main()
