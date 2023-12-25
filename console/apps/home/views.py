# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django import template
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.template import loader
from django.urls import reverse
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.home import models
from apps.home.forms import SignatureForm

import json
from django.views.decorators.csrf import csrf_exempt

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


#@login_required(login_url="/login/")
@csrf_exempt
def alert_notify(request):
    context = {'segment': 'alerts'}

    if request.method == 'POST':
        data = json.loads(request.body)

        new_alert = models.Alert.objects.create(
            signature_id=    data.get('signature_id', ''),
            source_ip=       data.get('source_ip', ''),
            destination_ip=  data.get('destination_ip', ''),
            source_port=     data.get('source_port', ''),
            destination_port=data.get('destination_port', ''),
            description=     data.get('description', ''),
            datetime=timezone.now(),
            tags=data.get('tags', [])
        )

        data['datetime'] = str(new_alert.datetime)
        data['source'] = "{}:{}".format(new_alert.source_ip, new_alert.source_port)
        data['destination'] = "{}:{}".format(new_alert.destination_ip, new_alert.destination_port)

        new_alert.save_base()

        channel_layer = get_channel_layer()
        # user_group_name = f"user_{alert_id}_group"
        user_group_name = "admin"
        async_to_sync(channel_layer.group_send)(
            user_group_name, {"type": "send_user", "data": data}
        )

        #return redirect('alerts/')
        return JsonResponse({"message": "Success notify"})

    return JsonResponse({"message": "Invalid request method"}, status=405)
    #html_template = loader.get_template('home/alerts.html')
    #return HttpResponse(html_template.render(context, request))


@login_required(login_url="/login")
def index(request):
    context = {'segment': 'index'}

    alert_count = count = models.Alert.objects.count()
    signature_count = count = models.Alert.objects.count()

    return render(
        request,
        "home/index.html",
        {
            "segment" : "index",
            "total_alerts" : alert_count,
            "total_signatures" : signature_count
        }
    )

@login_required(login_url="/login")
def profile_view(request):
    msg = None

    if request.method == "POST":
        form = SignatureForm(request.POST)
        print(request.POST)

        if form.is_valid():
            form.save()

        else:
            msg = "Ошибка вводимых данных"
    else:
        form = SignatureForm()

    return render(
        request,
        "home/profile.html",
        {
            "segment" : "profile",
            "form": form,
            "tags": dict(models.TAGS).keys(),
            "msg" : msg
        }
    )


@login_required(login_url="/login")
def alert_view(request):

    data = models.Alert.objects.all()

    return render(
        request,
        "home/alerts.html",
        {
            'segment': 'alerts',
            "notifications": data[::-1]
        }
    )


@login_required(login_url="/login")
def pages(request):
    context = {}
    # All resource paths end in .html.
    # Pick out the html file name from the url. And load that template.
    try:

        load_template = request.path.split('/')[-1]

        if load_template == 'admin':
            return HttpResponseRedirect(reverse('admin:index'))
        context['segment'] = load_template

        html_template = loader.get_template('home/' + load_template)
        return HttpResponse(html_template.render(context, request))

    except template.TemplateDoesNotExist:

        html_template = loader.get_template('home/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except:
        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))
