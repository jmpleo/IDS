# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.home import views
from apps.home import models

urlpatterns = [

    # The home page
    path('', views.index, name='home'),
    path("alerts/", views.alert_view, name="alerts"),
    path("alerts/notify/", views.alert_notify, name="alert_notify"),

    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
