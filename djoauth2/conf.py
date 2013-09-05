# coding: utf-8
from django.config import settings
from appconf import AppConf

class DJOAuthConf(AppConf):
  class Meta:
    prefix = 'djoauth'

  ACCESS_TOKEN_LENGTH = 30
  ACCESS_TOKEN_LIFETIME = 3600
  ACCESS_TOKENS_REFRESHABLE = True

  AUTHORIZATION_CODE_LENGTH = 30
  AUTHORIZATION_CODE_LIFETIME = 120

  CLIENT_KEY_LENGTH = 30
  CLIENT_SECRET_LENGTH = 30

  REFRESH_TOKEN_LENGTH = 30

  REALM = ''
  SSL_ONLY = True

