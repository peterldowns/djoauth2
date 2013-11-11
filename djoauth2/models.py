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

  def save(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      try:
        old_client = oldmodels.Client.objects.get(key=self.key)
      except oldmodels.Client.DoesNotExist:
        old_client = oldmodels.Client(key=self.key)
      old_client.secret = self.secret
      old_client.redirect_uri = self.redirect_uri
      old_client.description = self.description
      old_client.name = self.name
      old_client.user = self.user
      old_client.save()
    return super(Client, self).save(*args, **kwargs)

  def delete(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      for old_client in oldmodels.Client.objects.filter(key=self.key):
        old_client.delete()
    return super(Client, self).delete(*args, **kwargs)


class Scope(models.Model):
  name = models.CharField(unique=True, max_length=256, db_index=True)
  description = models.TextField()

  def __unicode__(self):
    return unicode(self.name)

  def __str__(self):
    return str(self.name)

  def save(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      try:
        old_scope = oldmodels.Scope.objects.get(name=self.name)
      except oldmodels.Scope.DoesNotExist:
        old_scope = oldmodels.Scope(name=self.name)
      old_scope.description = self.description
      old_scope.save()
    return super(Scope, self).save(*args, **kwargs)

  def delete(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      for old_scope in oldmodels.Scope.objects.filter(name=self.name):
        old_scope.delete()
    return super(Scope, self).delete(*args, **kwargs)


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
    self.save(propagate_changes=True)
    return self.invalidated

  def is_expired(self):
    return (self.invalidated or
            now() >= (self.date_created + timedelta(seconds=self.lifetime)))

  def __unicode__(self):
    return unicode(self.value)

  def __str__(self):
    return str(self.value)

  def save(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      if self.invalidated:
        for old_code in oldmodels.AuthorizationCode.objects.filter(
            value=self.value):
          old_code.delete()
      else:
        try:
          old_code = oldmodels.AuthorizationCode.objects.get(value=self.value)
        except oldmodels.AuthorizationCode.DoesNotExist:
          old_code = oldmodels.AuthorizationCode(value=self.value)
        # Create the old version of the client if it does not exist.
        self.client.save(propagate_changes=True)
        old_code.client = oldmodels.Client.objects.get(key=self.client.key)
        old_code.user = self.user
        old_code.value = self.value
        old_code.date_created = self.date_created
        old_code.expires_in = self.lifetime
        old_code.redirect_uri = self.redirect_uri

        old_code.save() # Create PK to allow access to M2M fields.
        old_scopes = []
        for scope in self.scopes.all():
          try:
            old_scope = oldmodels.Scope.objects.get(name=scope.name)
          except oldmodels.Scope.DoesNotExist:
            old_scope = oldmodels.Scope(name=scope.name)
          old_scope.description = scope.description
          old_scope.save()
          old_scopes.append(old_scope)
        old_code.scopes = old_scopes
        old_code.save()
    return super(AuthorizationCode, self).save(*args, **kwargs)

  def delete(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      for old_code in oldmodels.AuthorizationCode.objects.filter(
          value=self.value):
        old_code.delete()
    return super(AuthorizationCode, self).delete(*args, **kwargs)


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
    self.save(propagate_changes=True)
    return self.invalidated

  def is_expired(self):
    return (self.invalidated or
            now() >= (self.date_created + timedelta(seconds=self.lifetime)))

  def __unicode__(self):
    return unicode(self.value)

  def __str__(self):
    return str(self.value)

  def save(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      if self.invalidated:
        oldmodels.AccessToken.objects.filter(value=self.value).delete()
      else:
        try:
          old_token = oldmodels.AccessToken.objects.get(value=self.value)
        except oldmodels.AccessToken.DoesNotExist:
          old_token = oldmodels.AccessToken(value=self.value)
        old_token.user = self.user
        # Create the old version of the client if it does not exist.
        self.client.save(propagate_changes=True)
        old_token.client = oldmodels.Client.objects.get(key=self.client.key)
        old_token.date_created = self.date_created
        old_token.refresh_token = self.refresh_token
        old_token.expires_in = self.lifetime
        old_token.refreshable = self.refreshable

        old_token.save() # Create PK to allow access to M2M fields.
        old_scopes = []
        for scope in self.scopes.all():
          try:
            old_scope = oldmodels.Scope.objects.get(name=scope.name)
          except oldmodels.Scope.DoesNotExist:
            old_scope = oldmodels.Scope(name=scope.name)
          old_scope.description = scope.description
          old_scope.save()
          old_scopes.append(old_scope)
        old_token.scopes = old_scopes
        old_token.save()

    return super(AccessToken, self).save(*args, **kwargs)

  def delete(self, *args, **kwargs):
    if kwargs.pop('propagate_changes', False):
      from oauth2lib import models as oldmodels
      for old_token in oldmodels.AccessToken.objects.filter(value=self.value):
        old_token.delete()
    return super(AccessToken, self).delete(*args, **kwargs)

