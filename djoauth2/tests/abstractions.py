# coding: utf-8
import json
from base64 import b64encode
from hashlib import md5
from random import random

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client as TestClient
from django.test import TestCase
from django.test.client import RequestFactory

from djoauth2.models import AccessToken
from djoauth2.models import AuthorizationCode
from djoauth2.models import Client
from djoauth2.models import Scope

def remove_empty_parameters(params):
  for key, value in params.items():
    if value is None:
      del params[key]


class DJOAuth2TestClient(TestClient):
  def __init__(self, scope_names=None):
    # OAuth-related settings
    self.authorization_endpoint = '/oauth2/authorization/'
    self.token_endpoint = '/oauth2/token/'
    self.scope_names = scope_names or []

    # For internal use
    self.history = []
    self.access_token_value = None
    self.access_token_lifetime = None
    self.refresh_token_value = None
    super(DJOAuth2TestClient, self).__init__()

  @property
  def ssl_only(self):
    return settings.DJOAUTH2_SSL_ONLY

  @property
  def scope_string(self):
    return ' '.join(self.scope_names)

  @property
  def scope_objects(self):
    return Scope.objects.filter(name__in=self.scope_names)

  @property
  def last_response(self):
    return self.history[-1] if self.history else None

  def make_api_request(self,
                       access_token,
                       data=None,
                       method='POST',
                       use_ssl=None):
    factory = RequestFactory()

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only


    request_method = getattr(factory, method.lower())

    api_request = request_method('/url/does/not/matter', data or {}, **{
      # From http://codeinthehole.com/writing/testing-https-handling-in-django/
      'wsgi.url_scheme': 'https' if use_ssl else 'http'})

    api_request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + access_token.value

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    return api_request

  def access_token_request(self,
                           client,
                           custom=None,
                           headers=None,
                           method='POST',
                           header_auth=True,
                           use_ssl=None):

    data = {
        'client_id': client.key,
        'client_secret': client.secret,
        'redirect_uri': client.redirect_uri,
      }
    data.update(custom or {})
    remove_empty_parameters(data)

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only
    header_data = {
        'wsgi.url_scheme': 'https' if use_ssl else 'http'
      }

    if header_auth:
      header_data.update({
        'HTTP_AUTHORIZATION' : 'Basic ' + b64encode('{}:{}'.format(
          data.pop('client_id', ''), data.pop('client_secret', '')))})

    header_data.update(headers or {})
    remove_empty_parameters(header_data)

    request_method = getattr(self, method.lower())
    response = request_method(self.token_endpoint, data=data, **header_data)
    self.load_token_data(response)
    return response

  def request_token_from_authcode(self,
                                  client,
                                  authorization_code_value,
                                  **kwargs):
    custom = {
      'grant_type': 'authorization_code',
      'code': authorization_code_value,
    }
    custom.update(kwargs.pop('custom', {}))
    kwargs['custom'] = custom
    return self.access_token_request(client, **kwargs)

  def request_token_from_refresh_token(self,
                                  client,
                                  refresh_token_value,
                                  **kwargs):
    custom = {
      'grant_type': 'refresh_token',
      'refresh_token': refresh_token_value,
    }
    custom.update(kwargs.pop('custom', {}))
    kwargs['custom'] = custom
    return self.access_token_request(client, **kwargs)


  def load_token_data(self, response=None):
    response = response or self.last_response
    if not response:
      raise ValueError('No Response object form which to load data.')

    if response.status_code == 200:
      data = json.loads(response.content)
      self.access_token_value = data.get('access_token')
      self.access_token_lifetime = data.get('expires_in')
      self.refresh_token_value = data.get('refresh_token')
      return data
    else:
      self.access_token_value = None
      self.access_token_lifetime = None
      self.refresh_token_value = None
      return None


class DJOAuth2TestCase(TestCase):
  fixtures = (
      'auth_user.json',
      'djoauth2_client.json',
      'djoauth2_scope.json'
    )

  def initialize(self, **kwargs):
    self.user = User.objects.get(pk=1)
    self.client = Client.objects.get(pk=1)
    self.client2 = Client.objects.get(pk=2)
    self.oauth_client = DJOAuth2TestClient(**kwargs)

  def create_authorization_code(self, user, client, custom=None):
    object_params = {
      'user' : user,
      'client' : client,
      'redirect_uri' : client.redirect_uri,
      'scopes' : self.oauth_client.scope_objects,
    }
    object_params.update(custom or {})
    # Cannot create a new Django object with a ManyToMany relationship defined
    # in the __init__ method, so the 'scopes' parameter is set after
    # instantiation.
    scopes = object_params.pop('scopes')
    authorization_code = AuthorizationCode.objects.create(**object_params)
    if scopes:
      authorization_code.scopes = scopes
      authorization_code.save()
    return authorization_code

  def delete_authorization_code(self, authorization_code):
    if not isinstance(authorization_code, AuthorizationCode):
      raise ValueError("Not an AuthorizationCode");
    return authorization_code.delete()

  def create_access_token(self, user, client, custom=None):
    params = {
      'user' : user,
      'client' : client,
      'scopes' : self.oauth_client.scope_objects
    }
    params.update(custom or {})
    # Cannot create a new Django object with a ManyToMany relationship defined
    # in the __init__ method, so the 'scopes' parameter is set after
    # instantiation.
    scopes = params.pop('scopes')
    access_token = AccessToken.objects.create(**params)
    if scopes:
      access_token.scopes = scopes
      access_token.save()
    return access_token

  def delete_access_token(self, access_token):
    if not isinstance(access_token, AccessToken):
      raise ValueError("Not an AccessToken!")
    return access_token.delete()

  def create_scope(self, custom=None):
    random_string = md5(str(random())).hexdigest()
    params = {
      'name' : 'test-scope-' + random_string,
      'description' : 'an example test scope',
    }
    params.update(custom or {})
    return Scope.objects.create(**params)

  def delete_scope(self, scope):
    if not isinstance(scope, Scope):
      raise ValueError("Not a Scope!")
    return scope.delete()

  def assert_token_success(self, response):
    self.assertEqual(response.status_code, 200, response)
    # Check the response contents
    self.assertTrue(self.oauth_client.access_token_value)
    self.assertTrue(self.oauth_client.access_token_lifetime)
    self.assertTrue(self.oauth_client.refresh_token_value)

  def assert_token_failure(self, response, expected_error_code=None):
    self.assertNotEqual(response.status_code, 200, response)
    if expected_error_code:
      self.assertEqual(response.status_code, expected_error_code)
    else:
      # Should have received a 4XX HTTP status code
      self.assertTrue(str(response.status_code)[0] == '4')
    # Check the response contents
    self.assertIsNone(self.oauth_client.access_token_value)
    self.assertIsNone(self.oauth_client.access_token_lifetime)
    self.assertIsNone(self.oauth_client.refresh_token_value)
