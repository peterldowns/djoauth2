# coding: utf-8
from django.contrib import admin

from djoauth2.models import AccessToken
from djoauth2.models import AuthorizationCode
from djoauth2.models import Client
from djoauth2.models import Scope

admin.site.register(Client)
admin.site.register(Scope)
admin.site.register(AccessToken)
admin.site.register(AuthorizationCode)

