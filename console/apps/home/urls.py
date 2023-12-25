# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.home import views
from apps.home import models
from apps.home import consumers

urlpatterns = [
    path('', views.index, name='home'),
    path("profile", views.profile_view, name="profile"),
    path("alerts", views.alert_view, name="alerts"),
    path("alerts/notify", views.alert_notify, name="alert_notify"),

    re_path(r'^.*\.*', views.pages, name='pages')
]

websocket_urlpatterns = [
    # path("alerts/<int:user_id>", consumers.Consumer.as_asgi()),
    path("", consumers.Consumer.as_asgi()),
    path("alerts", consumers.Consumer.as_asgi()),
    path("profile", consumers.Consumer.as_asgi()),
    path("index", consumers.Consumer.as_asgi()),
]
