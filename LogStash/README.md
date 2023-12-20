# Описание атак обнаруживаемых модулем

## В логах auth.log
- Перебор пароля по ssh
- Перебор имени пользователя по ssh
- Большое количество неудачных попыток su
- Вызов sudo пользователя не состоящего в группе sudoers
- Уменьшение количества логов

## В логах access.log
- SQL Injection
- XSS
- Command Injection
- Reverse Shell
- Перебор дирректорий
- Уменьшение количества логов

## Инструменты автоматического тестирования обнаруживаемые с помощью логов
- feroxbuster
- w3af
- FFUF
- WFFUF
- DirBuster
- GoBuster
- Dirsearch
- Burp Suite
- sqlmap
- OWASP ZAP
- Nikto
- Nmap
- WhatWeb
- Netsparker