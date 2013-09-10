# coding: utf-8
import json
from hashlib import md5
from random import random

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client as TestClient
from django.test import TestCase

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
    self.ssl_only = settings.DJOAUTH2_SSL_ONLY

    # For internal use
    self.history = []
    self.access_token = None
    self.refresh_token = None
    self.lifetime = None
    super(DJOAuth2TestClient, self).__init__()

  @property
  def scope_string(self):
    return ' '.join(self.scope_names)

  @property
  def scope_objects(self):
    return Scope.objects.filter(name__in=self.scope_names)

  @property
  def last_response(self):
    return self.history[-1] if self.history else None

  def request_access_token(self,
                           client,
                           authorization_code_value,
                           custom=None,
                           method='POST',
                           use_ssl=None):
    data = {
        'code': authorization_code_value,
        'grant_type': 'authorization_code',
        'client_id': client.key,
        'client_secret': client.secret,
        'redirect_uri': client.redirect_uri,
      }
    data.update(custom or {})
    remove_empty_parameters(data)

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    response = self.post(self.token_endpoint, data=data, **{
      'wsgi.url_scheme': 'https' if use_ssl else 'http'})
    self.load_token_data(response)
    return response

  def request_refresh_token(self,
                            client,
                            refresh_token_value,
                            custom=None,
                            method='POST',
                            use_ssl=None):
    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    data = {
      'refresh_token': refresh_token_value,
      'grant_type': 'refresh_token',
      'client_id': client.key,
      'client_secret': client.secret,
      'scope': self.scope_string or None,
    }
    data.update(custom or {})
    remove_empty_parameters(data)

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    response = self.post(self.token_endpoint, data=data, **{
      'wsgi.url_scheme': 'https' if use_ssl else 'http'})
    self.load_token_data(response)
    return response

  def load_token_data(self, response=None):
    response = response or self.last_response
    if not response:
      raise ValueError('No Response object form which to load data.')

    if response.status_code == 200:
      data = json.loads(response.content)
      self.access_token = data.get('access_token')
      self.refresh_token = data.get('refresh_token')
      self.lifetime = data.get('expires_in')
      return data
    else:
      self.access_token = None
      self.refresh_token = None
      self.lifetime = None
      return None

  def display_response(self, response=None, max_length=10000):
    response = response or self.last_response
    print response.status_code
    print response.headers
    print response.content[:max_length]
    print ''
    print 'access_token:', repr(self.access_token)
    print 'refresh_token:', repr(self.refresh_token)
    print 'expires in:', repr(self.lifetime)


class DJOAuth2TestCase(TestCase):
  fixtures = (
      'auth_user.yaml',
      'djoauth2_client.yaml',
      'djoauth2_scope.yaml'
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
    self.assertEqual(response.status_code, 200, response.content)
    # Check the response contents
    self.assertTrue(self.oauth_client.access_token)
    self.assertTrue(self.oauth_client.refresh_token)
    self.assertTrue(self.oauth_client.lifetime)

  def assert_token_failure(self, response, expected_error_code=None):
    self.assertNotEqual(response.status_code, 200, response.content)
    if expected_error_code:
      self.assertEqual(response.status_code, expected_error_code)
    else:
      # Should have received a 4XX HTTP status code
      self.assertTrue(str(response.status_code)[0] == '4')
    # Check the response contents
    self.assertIsNone(self.oauth_client.access_token)
    self.assertIsNone(self.oauth_client.refresh_token)
    self.assertIsNone(self.oauth_client.expires_in)


class TestAccessToken(DJOAuth2TestCase):
  def test_pass_no_redirect_defaults_to_registered(self):
    """ If the OAuth client has registered a redirect uri, it is OK to
    not explicitly pass the same URI again.
    """
    # Create a client with a specific redirect URI.
    self.initialize()

    # Create an authorization code without a redirect URI.
    authcode = self.create_authorization_code(
        self.user,
        self.client,
        {'redirect_uri' : None})

    # Override the default redirect param to not exist.
    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'redirect_uri' : None,
        })

    self.assert_token_success(response)

