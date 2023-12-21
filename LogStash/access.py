import logdissect 
import os
import json
import re
from datetime import datetime
from collections import defaultdict
from alert import send_post
from BDReq import BDRequests

def form_data(date_stamp):
    input_datetime = datetime.strptime(date_stamp, '%Y%m%d%H%M%S')
    formatted_date = input_datetime.strftime('%Y-%m-%d %H:%M:%S')
    return formatted_date

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
                    send_post("-", "local", "local", "local", "Уменьшилось количество логов", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ["local", "logs"])
                    print("Уменьшилось количество логов")
    except FileNotFoundError:
        return
    
#Парсер access логов
def access_check(filename, filter_flag = True):
    #Парсинг логов и разбиение их на поля
    parser = logdissect.parsers.webaccess.ParseModule()
    data = parser.parse_file(filename)
    count_log = len(data['entries'])
    
    #Проверка количества логов
    check_count_log(filename,data)

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

def check_by_signatures(data):
    #Получение списка сигнатур
    BD = BDRequests()
    signatures = BD.get_signatures()

    #Применение сигнатур
    for log in data['entries']:
        for signature in signatures:
            regexpatern = signature[1]
            match = re.search(regexpatern, log['raw_text'])
            if match:
                formatted_date = form_data(log['numeric_date_stamp'])
                tags = signature[3].split(",")
                send_post(signature[0],log['source_host'],"?","80",signature[2],formatted_date, tags)
                print(f"Сработала сигнатура: {signature[2]}, ip атакующего {log['source_host']}, время: {log['date_stamp']}")

def check_directory_fuzz(data):
    #Получение списка сигнатур
    BD = BDRequests()
    signatures = BD.get_fuzzer_sig()

    #Применение сигнатур
    for log in data['entries']:
        for signature in signatures:
            regexpatern = signature[1]
            match = re.search(regexpatern, log['raw_text'])
            if match:
                signatures.remove(signature)
                formatted_date = form_data(log['numeric_date_stamp'])
                tags = signature[3].split(",")
                send_post(signature[0],log['source_host'],"?","80",signature[2],formatted_date, tags)
                print(f"Сработала сигнатура: {signature[2]}, ip атакующего {log['source_host']}, время: {log['date_stamp']}")       

def main():
    data = access_check("/var/log/nginx/access.log", False)
    check_by_signatures(data)
    check_directory_fuzz(data)


if __name__ == '__main__':
    main()