FROM python:3.9

# ARG DATABASE_HOSTNAME
# ARG DATABASE_PORT
# ARG DATABASE_NAME
# ARG DATABASE_USER
# ARG DATABASE_PASSWORD

COPY . .

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install python dependencies
RUN pip install --upgrade pip --timeout=1000
RUN pip install --no-cache-dir -r requirements.txt --timeout=1000

# running migrations
# RUN python manage.py makemigratoins && \
#     python manage.py migrate

# gunicorn
# CMD ["gunicorn", "--config", "gunicorn-cfg.py", "core.wsgi"]
# CMD ["python", "manage.py", "runserver", "0.0.0.0:5005"]

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

