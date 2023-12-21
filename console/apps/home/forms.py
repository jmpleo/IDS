# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm
from apps.home.models import Signature


class SignatureForm(forms.ModelForm):

    source_ip = forms.CharField(widget=forms.TextInput(
            attrs={ "placeholder": "127.0.0.1", "class": "form-control" }))

    source_port = forms.CharField(widget=forms.TextInput(
            attrs={ "placeholder": "80", "class": "form-control" }))

    destination_ip = forms.CharField(widget=forms.TextInput(
            attrs={ "placeholder": "127.0.0.1", "class": "form-control" }))

    destination_port = forms.CharField(widget=forms.TextInput(
            attrs={ "placeholder": "80", "class": "form-control" }))

    regex = forms.CharField(widget=forms.TextInput(
            attrs={ "class": "form-control" }))

    regex_hex = forms.CharField(widget=forms.TextInput(
            attrs={ "class": "form-control" }))

    protocol = forms.CharField(widget=forms.TextInput(
            attrs={ "class": "form-control" }))


    class Meta:
        model = Signature
        fields = (
            'source_ip',
            'source_port',
            'destination_ip',
            'destination_port',
            'regex',
            'regex_hex',
            'protocol',
            'tags'
            )
