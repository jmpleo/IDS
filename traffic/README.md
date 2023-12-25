## Build

Для сброки необходимы библиотеки `pq`, `pcap`, `curl`, `pcap++`.

``` bash
sudo apt install libpq5 libpcap0.8 libcurl4 build-essential
```

[pcap++](https://pcapplusplus.github.io/docs/install/linux)

Соберите исходные файлы используя `make`:

```bash
make
```

или `cmake`

```bash
cmake -B build
cd build && make
```

`dpkg`

```bash
sudo dpkg -i sniffer.deb
```





## Файлы конфигурации

- `/opt/sniffer/filter.txt`. Файд конфигурации фильтров BPF.

  ```
   not port 5432 and ip
  ```

- `/opt/sniffer/confDB.txt` - Файл конфигурации базы данных. Например:

  ```
  user=ids port=5444 password=ids host=localhost dbname=ids
  ```


