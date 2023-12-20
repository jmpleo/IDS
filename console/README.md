

## API

Для оповещения консоли о сработанной сигнатуре, необходимо отправить `POST` запрос.

### POST

1. `/alerts/notify/`

   ```json
   {
   	"alert_id":"",
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
       "alert_id": "1",
       "signature_id": "1",
       "source_ip": "81.16.0.1",
       "destination_ip": "10.0.0.1",
       "source_port": 1234,
       "destination_port": 5678,
       "description": "Example alert",
       "timestamp":"10.12.2023",
       "tags": ["bruteforce", "http"]
   }' http://<console>/alerts/notify/
   ```

   #### Python

   ```python
   import request

   requests.post(
       url='http://<console>/alerts/notify/',
       headers={
           "Content-Type" : "application/json"
       },
       json={
           "alert_id": "123",
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



### GET

coming soon...

