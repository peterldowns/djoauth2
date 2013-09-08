# coding: utf-8
from django.conf import settings

from appconf import AppConf

class DJOAuth2Conf(AppConf):
  class Meta:
    prefix = 'djoauth2'

  ACCESS_TOKEN_LENGTH = 30
  ACCESS_TOKEN_LIFETIME = 3600
  ACCESS_TOKENS_REFRESHABLE = True

  AUTHORIZATION_CODE_LENGTH = 30
  # The specification ( http://tools.ietf.org/html/rfc6749#section-4.1.1 )
  # recommends a liftime of 10 minutes.
  AUTHORIZATION_CODE_LIFETIME = 600

  CLIENT_KEY_LENGTH = 30
  CLIENT_SECRET_LENGTH = 30

  REFRESH_TOKEN_LENGTH = 30

  REALM = ''
  REQUIRE_STATE = True
  SSL_ONLY = True

