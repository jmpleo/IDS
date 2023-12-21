#!/bin/sh

echo $DATABASE_HOSTNAME

python manage.py makemigrations && \
python manage.py migrate && \
python manage.py runserver 0.0.0.0:5005
