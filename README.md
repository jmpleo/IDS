# IDS

Система Обнаружения Вторжений удовлетворяющая перечисленным ниже требованиям **ГОСТ Р ИСО/МЭК 15408-3-2008**.

### Требования безопасности БО

- `FAU_GEN.1`
- `FAU_GEN.2`
- `FAU_SAR.1`
- `FMT_SMR.1`
- `FMT_MOF.1`
- `FMT_MTD.1`
- `FID_COL_EXT.2 ` (* данные будут браться из pcap файла)
- `FID_ANL_EXT.2`
- `FID_MTH_EXT.1.1` (* без эвристического метода анализа)
- `FID_RCT_EXT.1`
- `FID_INF_EXT.1`

### Функции ОУД

- `AGD`

- `ADCHGS.1`


## Развертывание

Вам необходимы будут `docker` и `docker-compose`.

### Виртуальное окружение

Измените файлы виртуальных окружений `db/.env`, `console/.env`, `logstash/.env`,  касательно ваших конфигураций. Например:

- `console/.env` - Настройки подключения к БД модуля `console`, а также настройки сервис`redis`

  ```bash
  REDIS_HOSTNAME=redis
  REDIS_PORT=6379
  DEBUG=True
  SECRET_KEY=S3cr3t_K#Key
  DATABASE_HOSTNAME=postgres
  DATABASE_PORT=5432
  DATABASE_NAME=ids
  DATABASE_USER=ids
  DATABASE_PASSWORD=ids
  ```

  

- `logstash/.env` - Настройки подключения к БД модуля `LogStash` 

  ```bash
  DATABASE_HOSTNAME=localhost
  DATABASE_PORT=5444
  DATABASE_NAME=ids
  DATABASE_USER=ids
  DATABASE_PASSWORD=ids
  ```

  

- `db/.env` - Настройки инициализации БД.

  ```bash
  POSTGRES_DB=ids
  POSTGRES_USER=ids
  POSTGRES_PASSWORD=ids
  ```



### Docker-compose

Теперь запустите/соберите все модули используя `docker-compose`:

```bash
docker-compose up -d
```



