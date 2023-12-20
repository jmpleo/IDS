import logdissect 
from datetime import datetime
import re
from collections import defaultdict
import json
import os

#Функция фильтрации уже провереных логов
def filter_log(filename, data):
    #Чтение из файла дату последнего лога который попал под проверку и проверка совпадения количества
    if not os.path.exists('checked.json'):
        return data
    with open('checked.json', 'r') as file:
        json_data = json.load(file)
        if filename not in json_data:
            return data
        last_checked_log_time = json_data.get(filename,'')[0]

    #Фильтрация уже провереных логов
    now_time = datetime.now().strftime('%Y%m%d%H%M%S')
    val = f"{last_checked_log_time}-{now_time}"
    filter = logdissect.filters.range.FilterModule()
    data = filter.filter_data(data, value=val)
    
    return data
    
def check_count_log(filename, data):
    now_count_log = len(data['entries'])
    try:
        with open('checked.json', 'r') as file:
            jsond = json.load(file)  # Загрузка данных из JSON-файла
            if filename in jsond:
                last_count_log = jsond.get(filename,'')[1]
                if last_count_log > now_count_log:
                    print("Уменьшилось количество логов")
    except FileNotFoundError:
        return

#Парсер системных логов
def syslog_check(filename, filter_flag = True):
    #Парсинг логов и разбиение их на поля
    parser = logdissect.parsers.syslog.ParseModule()
    data = parser.parse_file(filename)
    count_log = len(data['entries'])

    #Проверка количества логов
    check_count_log(filename,data)

    #Фильтрация
    if filter_flag:
        data = filter_log(filename,data)
    
    #Изменение значения последних провереных логов
    if len(data['entries']) != 0:
        last_checked_log_time = str(int(data['entries'][len(data['entries']) - 1]['numeric_date_stamp']) + 1)
        
        #Запись значений в JSON
        try:
            with open('checked.json', 'r') as file:
                jsond = json.load(file)  # Загрузка данных из JSON-файла
        except FileNotFoundError:
            jsond = {}
        jsond[filename] = [last_checked_log_time,count_log]
        with open('checked.json', 'w') as file:
            json.dump(jsond, file)
    return data

#Проверка атаки перебором пароля на ssh
def check_ssh_brute_force(data):
    #Разбиваем логи по ip адресу атакующего
    bad_src = defaultdict(lambda: [0, None])
    for log in data['entries']:
        if "Failed password for" in log['raw_text'] and "ssh" in log['raw_text'] and "invalid" not in log['raw_text']: 
            ip_src = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log['message'])[0]
        
            #Подсчет количества для конкретного ip
            if ip_src in bad_src:
                bad_src[ip_src][0] += 1  
            else:
                bad_src[ip_src] = [1,log['date_stamp']] 

    #Проверяем количество строк удовлетворяющих критерию атаки
    for ip in bad_src:
        if bad_src[ip][0] >= 5:
            print(f"Попытка перебора пароля c ip: {ip} атака начата {bad_src[ip][1]}")

#Проверка перебора полльзователя
def check_ssh_user_brute(data):
    #Разбиваем логи по ip адресу атакующего
    bad_src = defaultdict(lambda: [0, None])
    for log in data['entries']:
        if "Failed password for invalid" in log['raw_text'] and "ssh" in log['raw_text']: 
            ip_src = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log['message'])[0]
            
            #Подсчет количества для конкретного ip
            if ip_src in bad_src:
                bad_src[ip_src][0] += 1  
            else:
                bad_src[ip_src] = [1,log['date_stamp']] 

    #Проверяем количество строк удовлетворяющих критерию атаки
    for ip in bad_src:
        if bad_src[ip][0] >= 5:
            print(f"Попытка перебора пользователя c ip: {ip} атака начата {bad_src[ip][1]}")

#Много неудачных попыток su
def many_su_errors(data):
    #Разбиваем логи по имени пользователя и аккаунту к которому делают su
    bad_logs = defaultdict(lambda: [0, None])
    for log in data['entries']:
        if "authentication failure" in log['raw_text'] and "su" in log['raw_text']:
            matches = re.search(r'ruser=([^\s]+).*?user=([^\s]+)', log['message'])
            if matches:
                ruser = matches.group(1)
                user = matches.group(2)
                constr_ruser_user = f"{ruser}:{user}"
                
                #Подсчет количества для конктретного пользователя
                if constr_ruser_user in bad_logs:
                    bad_logs[constr_ruser_user][0] += 1 
                else:
                    bad_logs[constr_ruser_user] = [1, log['date_stamp']]    

    #Проверяем количество строк удовлетворяющих критерию атаки
    for constr_ruser_user in bad_logs:
        if bad_logs[constr_ruser_user][0] >= 3:
            ruser,user = constr_ruser_user.split(':')
            print(f"Много попыток выполнить su к пользователю {user}, пользователем {ruser}, атака начата {bad_logs[constr_ruser_user][1]}: Возможен перебор пароля")


#Проверка ошибок свзязаных с тем что пользователь не в группе sudoers
def sudoers_error(data):
    for log in data['entries']:
        if "user NOT in sudoers" in log['raw_text']:
            username = re.findall(r"([^\s]+) : user NOT in sudoers", log['message'])[0]
            print(f"Попытка вызвать sudo от пользователя не являющегося членом группы sudoers, имя пользователя: {username}, время: {log['date_stamp']}")



def main():
    data = syslog_check('/var/log/auth.log', False)
    check_ssh_brute_force(data)
    check_ssh_user_brute(data)
    many_su_errors(data)
    sudoers_error(data)

if __name__ == '__main__':
    main()