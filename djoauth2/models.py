# coding: utf-8
from datetime import datetime
from datetime import timedelta

from django.contrib.auth.models import User
from django.db import models
from django.utils.timezone import now

from djoauth2.conf import settings
from djoauth2.helpers import make_authorization_code
from djoauth2.helpers import make_bearer_token
from djoauth2.helpers import make_client_key
from djoauth2.helpers import make_client_secret


class Client(models.Model):
  user = models.ForeignKey(User)
  name = models.CharField(max_length=256)
  description = models.TextField(null=True, blank=True)
  image_url = models.URLField(null=True, blank=True)
  redirect_uri = models.URLField(null=False, blank=False)
  key = models.CharField(
    db_index=True,
    default=make_client_key(settings.DJOAUTH2_CLIENT_KEY_LENGTH),
    max_length=settings.DJOAUTH2_CLIENT_KEY_LENGTH,
    unique=True,
  )
  secret = models.CharField(
    db_index=True,
    default=make_client_secret(settings.DJOAUTH2_CLIENT_SECRET_LENGTH),
    max_length=settings.DJOAUTH2_CLIENT_SECRET_LENGTH,
    unique=True,
  )

  def __unicode__(self):
    return unicode(self.name)

  def __str__(self):
    return str(self.name)


class Scope(models.Model):
  name = models.CharField(unique=True, max_length=256, db_index=True)
  description = models.TextField()

  def __unicode__(self):
    return unicode(self.name)

  def __str__(self):
    return str(self.name)


class AuthorizationCode(models.Model):
  client = models.ForeignKey(Client)
  user = models.ForeignKey(User)
  date_created = models.DateTimeField(auto_now_add=True)
  lifetime = models.PositiveIntegerField(
      default=lambda: settings.DJOAUTH2_AUTHORIZATION_CODE_LIFETIME)
  invalidated = models.BooleanField(default=False)
  redirect_uri = models.URLField(null=True, blank=True)
  scopes = models.ManyToManyField(Scope, related_name='authorization_codes')
  value = models.CharField(
    db_index=True,
    default=make_authorization_code(
      settings.DJOAUTH2_AUTHORIZATION_CODE_LENGTH),
    max_length=settings.DJOAUTH2_AUTHORIZATION_CODE_LENGTH,
    unique=True,
  )

  def get_scope_names_set(self):
    return {s.name for s in self.scopes.all()}

  def has_scope(self, *scope_names):
    return self.get_scope_names_set() >= set(scope_names)

  def invalidate(self):
    self.invalidated = True
    self.save()
    return self.invalidated

  def is_expired(self):
    return (self.invalidated or
            now() >= (self.date_created + timedelta(seconds=self.lifetime)))

  def __unicode__(self):
    return unicode(self.value)

  def __str__(self):
    return str(self.value)


class AccessToken(models.Model):
  client = models.ForeignKey(Client)
  date_created = models.DateTimeField(auto_now_add=True)
  lifetime = models.PositiveIntegerField(
      default=lambda: settings.DJOAUTH2_ACCESS_TOKEN_LIFETIME)
  invalidated = models.BooleanField(default=False)
  authorization_code = models.ForeignKey(
      AuthorizationCode, related_name='access_tokens', blank=True, null=True)
  refreshable = models.BooleanField(
      default=lambda: settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE)
  refresh_token = models.CharField(
    blank=True,
    db_index=True,
    default=make_bearer_token(settings.DJOAUTH2_REFRESH_TOKEN_LENGTH),
    max_length=settings.DJOAUTH2_REFRESH_TOKEN_LENGTH,
    null=True,
    unique=True,
  )
  scopes = models.ManyToManyField(Scope, related_name='access_tokens')
  user = models.ForeignKey(User)
  value = models.CharField(
    db_index=True,
    default=make_bearer_token(settings.DJOAUTH2_ACCESS_TOKEN_LENGTH),
    max_length=settings.DJOAUTH2_ACCESS_TOKEN_LENGTH,
    unique=True,
  )

  def get_scope_names_set(self):
    return {s.name for s in self.scopes.all()}

  def has_scope(self, *scope_names):
    return self.get_scope_names_set() >= set(scope_names)

  def invalidate(self):
    self.invalidated = True
    self.save()
    return self.invalidated

  def is_expired(self):
    return (self.invalidated or
            now() >= (self.date_created + timedelta(seconds=self.lifetime)))

  def __unicode__(self):
    return unicode(self.value)

  def __str__(self):
    return str(self.value)

