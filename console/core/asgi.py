# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import core.urls


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# application = get_asgi_application()

application = ProtocolTypeRouter(
    {
        # handle http/https requests
        "http": get_asgi_application(),
        # handle ws/wss requests
        "websocket": AuthMiddlewareStack(
            URLRouter(
                core.urls.websocket_urlpatterns
            )
        )
    }
)
