# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils import timezone


TAGS = (
    ("http", "HTTP"),
    ("bruteforce", "Brute Force"),
    ("ssh", "SSH")
)

TAGS

class Signature(models.Model):
    source_ip = models.TextField()
    destination_ip = models.TextField()
    source_port = models.TextField()
    destination_port = models.TextField()
    regex = models.TextField()
    regex_hex = models.TextField()
    protocol = models.TextField()
    tags = ArrayField(
        models.CharField(
            max_length=50,
            choices=TAGS
            )
        )

    def __str__(self):
        return self.regex


class Alert(models.Model):
    signature_id = models.IntegerField()
    source_ip = models.CharField(max_length=15)
    destination_ip = models.CharField(max_length=15)
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    description = models.TextField()
    datetime = models.DateTimeField(default=timezone.now)
    tags = ArrayField(
        models.CharField(
            max_length=50,
            choices=TAGS
            )
        )

    def __str__(self):
        return self.description
