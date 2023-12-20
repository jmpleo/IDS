INSERT INTO public.acces_log_signature(
	pattern, description, tag)
	VALUES 
	('.*SELECT.*', 'Поиск оператора SELECT, который может указывать на попытку извлечения данных', 'SQL Injection, Web, Web'),
	('.*DELETE.*', 'Поиск оператора DELETE, используемого для удаления данных', 'SQL Injection, Web'),
	('.*UPDATE.*', 'Поиск оператора UPDATE, используемого для обновления данных', 'SQL Injection, Web'),
	('.*INSERT.*', 'Поиск оператора INSERT, который может быть использован для вставки данных', 'SQL Injection, Web'),
	('.*DROP.*', 'Поиск оператора DROP, который может быть использован для удаления таблиц или баз данных', 'SQL Injection, Web'),
	('.*<script>.*', 'Поиск тега <script>, который может использоваться для внедрения вредоносного JavaScript кода', 'XSS, Web'),
	('.*onerror.*', 'Поиск строки onerror=, которая может указывать на попытку выполнения кода при возникновении ошибки', 'XSS, Web'),
	('.*javascript:.*', 'Поиск строки javascript:, которая может указывать на использование JavaScript', 'XSS, Web'),
	('.*document.cookie.*', 'Поиск строки document.cookie, которая может использоваться для доступа к куки файлам', 'XSS, Web'),
	('.*alert\(.*', 'Поиск функции alert(), которая может использоваться для отображения всплывающих окон', 'XSS, Web'),
	('.*exec.*', 'Поиск попыток выполнения системных команд через exec', 'Command Injection, Web'),
	('.*whoami.*', 'Поиск команды для просмотра содержимого директории', 'Command Injection, Web'),
	('.*cmd.*', 'Поиск попыток выполнения системных команд через cmd', 'Command Injection, Web'),
	('.*nc\s+-e\s+\/bin\/sh.*', 'Поиск использования утилиты nc (netcat) для установки обратного шелла', 'Reverse Shell, Web'),
	('.*bash\s+-i\s+>&\s+\/dev\/tcp\/.*' , 'Поиск использования bash для установки обратного шелла', 'Reverse Shell, Web'),
	('.*python\s+-c\s+\''import\s+socket,subprocess,os.*', 'Попытка использования Python для установки обратного шелла', 'Reverse Shell, Web'),
	('.*perl\s+-MIO\s+-e.*', 'Попытка использования Perl для установки обратного шелла', 'Reverse Shell, Web'),
	('.*rm\s+\/tmp\/f;mkfifo\s+\/tmp\/f;cat\s+\/tmp\/f\|\/bin\/sh\s+-i\s+2>&1\|nc\s+.*', 'Попытка установки обратного шелла с использованием fifo и netcat', 'Reverse Shell');
    
INSERT INTO public.fuzzers_signature(
	pattern, description, tag)
	VALUES 
    ('.*feroxbuster.*', 'Фаззер feroxbuster', 'Fuzzer, Web')
	('.*w3af.*', 'Фаззер w3af', 'Fuzzer, Web'),
    ('.*Fuzz Faster U Fool.*', 'Фаззер FFUF', 'Fuzzer, Web'),
    ('.*Wfuzz.*', 'Фаззер WFFUF', 'Fuzzer, Web'),
    ('.*DirBuster.*', 'Фаззер DirBuster', 'Fuzzer, Web'),
    ('.*gobuster.*', 'Фаззер GoBuster', 'Fuzzer, Web'),
    ('.*Dirsearch.*', 'Фаззер Dirsearch', 'Fuzzer, Web'),
    ('.*Burp Suite.*', 'Инструмент для тестирования на уязвимости Burp Suite', 'Fuzzer, Web'),
    ('.*sqlmap.*', 'Фаззер sqlmap для автоматизации тестирования на SQL инъекции', 'Fuzzer, Web'),
    ('.*OWASP ZAP.*', 'OWASP Zed Attack Proxy - инструмент для тестирования безопасности', 'Fuzzer, Web'),
    ('.*Nikto.*', 'Nikto - инструмент для сканирования веб-серверов', 'Fuzzer, Web'),
    ('.*Nmap.*', 'Инструмент для тестирования на уязвимости Nmap', 'Fuzzer, Web'),
    ('.*WhatWeb.*', 'Инструмент для тестирования на уязвимости WhatWeb', 'Fuzzer, Web'),
    ('.*Netsparker.*', 'Netsparker - инструмент для автоматизированного тестирования на уязвимости', 'Fuzzer, Web');
	