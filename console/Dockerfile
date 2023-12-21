FROM python:3.9

COPY . .

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install python dependencies
 RUN pip install --upgrade pip --timeout=1000
RUN pip install --no-cache-dir -r requirements.txt --timeout=1000

RUN echo $DATABASE_HOSTNAME

# running migrations
RUN python manage.py makemigratoins && \
    python manage.py migration

# gunicorn
# CMD ["gunicorn", "--config", "gunicorn-cfg.py", "core.wsgi"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:5005"]

