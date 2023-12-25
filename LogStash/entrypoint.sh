#!/bin/sh

crontab -l > cron.tmp

echo "*/5 * * * * python /main.py" >> cron.tmp

crontab cron.tmp

rm cron.tmp

tail -f /dev/null
