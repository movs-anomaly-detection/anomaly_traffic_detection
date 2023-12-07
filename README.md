# Детектирование аномальных соединений в интернет-трафике

Здесь будет проводиться исследование данных сессией интернет-трафика, разработка модели по детектированию аномалий в интернет-сессиях и сервис по детектированию аномалий соединений интернет-трафика.

# Сбор данных

Данные собирали при помощи скрипта. Логировали трафик при помощи Wireshark'a. Данные лежат на яндекс-диске: https://disk.yandex.ru/d/SRpp1XyYiXiZlg. На данном этапе хранятся в json-файлах.

# Описание данных

Данные, на которых будет обучена модель, на данном этапе делятся на две части: данные записанных при помощи Wireshark сессий, и данные нод (узлов в сети, будем считать что у каждого из них есть соответствующий единственный и уникальный ip-адрес вида xxx.xxx.xxx.xxx).

Данные логируемых сессией (название sessions_of_j) представляют из себя массив со следующими узлами для интернет-сессий (http, tls и возможно quic, если в нём будет tls):
1. IP адрес, с которого отправляются сообщения (строка, возможна конвертация в вектор)
2. Массив Packets
3. Handshake - данные о рукопожатии (если пустой, то рукопожатия в сессии не было)
4. Порт, с которого отправляются сообщения (число)
5. Протокол управления передачей данных или же транспортный протокол (строка, возможна конвертация в перечисление, то есть число)

Packets включает в себя следующие данные:
1. Timestamp (метка времени сессии, вещественное число)
2. TLS - опциональный массив данных с узлами работы интернет-протокола, включающими в себя рукопожатие и его параметры для установления безопасного соединения (договоренности сервиса и клиента об условиях безопасного соединения - шифры, хэш функции), extencion, который дополняет (имя сервера, уточнение по сертификатам - какие могут быть типы, уточнение, какой протокол будет использоваться), по этим уточнениям детектят соединение на предмет наличия или отсутствия зловредности. Данные сертификатов: данные об их количестве и является ли один из них самоподписным, signatureAlgorithm_element.id и Responder_id, некоторые из них более уязвимы, и важны для детекции аномалии.
3. DNS - опциональное сообщение DNS-протокола
4. QUIC - опциональный массив сообщений QUIC-протокола
5. HTTP - сообщения http
6. HTTP2 - сообщения http2

Данные нод (все файлы с названием nodes_of_j) представляют из себя массив со следующими узлами:
1. IP адрес - с которого отправляются сообщения
2. Порт, с которого отправляются сообщения
3. Протокол управления передачей данных

Данные нод потребуются нам для последующей склейки.

# Результаты экспериментов с моделям
![image.png](attachment:image.png)
