# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User
from channels.generic.websocket import AsyncWebsocketConsumer


class Alert(models.Model):
    alert_id = models.CharField(max_length=100)
    sig_id = models.CharField(max_length=100)
    source_ip = models.CharField(max_length=100)
    destination_ip = models.CharField(max_length=100)
    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    description = models.TextField()
    tags = models.JSONField()

    def __str__(self):
        return self.alert_id
