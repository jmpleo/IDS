# Generated by Django 3.2.6 on 2023-12-21 12:59

import django.contrib.postgres.fields
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('signature_id', models.IntegerField()),
                ('source_ip', models.CharField(max_length=15)),
                ('destination_ip', models.CharField(max_length=15)),
                ('source_port', models.IntegerField()),
                ('destination_port', models.IntegerField()),
                ('description', models.TextField()),
                ('datetime', models.DateTimeField(default=django.utils.timezone.now)),
                ('tags', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(choices=[('http', 'HTTP'), ('bruteforce', 'Brute Force'), ('sqlinjection', 'SQL Injection'), ('ssh', 'SSH')], max_length=50), size=None)),
            ],
        ),
    ]