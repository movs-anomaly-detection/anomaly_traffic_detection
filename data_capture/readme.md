# Получение данных

Скрипт pcap_to_json.py при запуске принимает от 2 до 3 аргументов:
1. Маска файлов (сначала вычисляется директория файлов по последнему бэкслэшу, остальное считается маской);
2. Директория куда надо сохранить файлы или яндекс-диск (последнее определяется по префиксу "@yadisk/");
3. Файл логов или ключ по которому расшифровываются TLS/QUIC-сообщения (опциональный аргумент).

Скрипт generate_pcap.py при запуске принимает от 2 до 3 аргументов:
1. Имя файла, где указан список url-ов по которым надо проходить;
2. Шаблонное имя файла сохранения pcap-файлов;
3. Файл логов, куда записываются secret-ы для расшифровки TLS-сессий (опциональный аргумент).
