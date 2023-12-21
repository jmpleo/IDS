

## Quick start

Измените файл `.env` касательно ваших настроек

```
REDIS_HOSTNAME=redis
REDIS_PORT=6379
DEBUG=True
SECRET_KEY=S3cr3t_K#Key
SERVER=localhost
```

### Docker

Соберите сервисы и запустите используя `docker-compose`:

```bash
docker-compose up
```

### Host

 Установите зависимости и запустите сервер консоли

```bash
pipenv --python 3.9
pipenv install -r requirements.txt
pipenv run python3 manage.py runserver 0.0.0.0:85
```



## Dev API

Для оповещения консоли о сработанной сигнатуре, необходимо отправить `POST` запрос.

### POST

1. `/alerts/notify`

   ```json
   {
   	"signature_id":"",
   	"source_ip":"",
   	"destination_ip":"",
   	"source_port":"",
   	"destination_port":"",
   	"description":"",
   	"timestamp":"",
   	"tags":[]
   }
   ```
   
   #### CURL
   
   ```bash
   curl -X POST \
   	-H "Content-Type: application/json" \
   	-d'{
       "signature_id": "1",
       "source_ip": "81.16.0.1",
       "destination_ip": "10.0.0.1",
       "source_port": 1234,
       "destination_port": 5678,
       "description": "Example alert",
       "timestamp":"10.12.2023",
       "tags": ["bruteforce", "http"]
   }' http://<console>/alerts/notify
   ```
   
   #### Python

   ```python
   import requests
   
   requests.post(
       url='http://<console>/alerts/notify',
       headers={
           "Content-Type" : "application/json"
       },
       json={
           "signature_id": "456",
           "source_ip": "192.168.0.1",
           "destination_ip": "10.0.0.1",
           "source_port": "1234",
           "destination_port": "5678",
           "description": "Example alert",
           "timestamp":"10.12.2023",
           "tags": ["tag1", "tag2"]
       }
   )
   ```
   #### C++
   
   ```c++
   #include <iostream>
   #include <curl/curl.h>
   
   int main() {
       CURL *curl;
       CURLcode res;
   
       curl_global_init(CURL_GLOBAL_DEFAULT);
   
       curl = curl_easy_init();
       if (curl) {
           curl_easy_setopt(curl, CURLOPT_URL, "http://<console>/alerts/notify");
   
           struct curl_slist *headers = NULL;
           headers = curl_slist_append(headers, "Content-Type: application/json");
           curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
   
           const char *data = R"({
               "signature_id": "1",
               "source_ip": "81.16.0.1",
               "destination_ip": "10.0.0.1",
               "source_port": 1234,
               "destination_port": 5678,
               "description": "Example alert",
               "timestamp": "10.12.2023",
               "tags": ["bruteforce", "http"]
           })";
           curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
   
           res = curl_easy_perform(curl);
           if (res != CURLE_OK) {
               std::cerr << "Ошибка при выполнении запроса: " << curl_easy_strerror(res) << std::endl;
           }
   
           curl_easy_cleanup(curl);
           curl_slist_free_all(headers);
       }
   
       curl_global_cleanup();
   
       return 0;
   }
   ```
   

​	

### GET

coming soon...

