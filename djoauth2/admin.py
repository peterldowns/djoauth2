# coding: utf-8
from django.contrib import admin
from djoauth.models import Client, Scope, AccessToken, AuthorizationCode

admin.site.register(Client)
admin.site.register(Scope)
admin.site.register(AccessToken)
admin.site.register(AuthorizationCode)

