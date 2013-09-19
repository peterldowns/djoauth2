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
    # OAuth-related settings.
    self.authorization_endpoint = '/oauth2/authorization/'
    self.token_endpoint = '/oauth2/token/'
    self.scope_names = scope_names or []

    # For internal use.
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

  def make_authorization_request(self,
                                 client_id,
                                 scope_string,
                                 custom=None,
                                 endpoint='/fake/endpoint/',
                                 method='GET',
                                 use_ssl=None):
    if use_ssl is None:
      use_ssl = self.ssl_only

    data = {
        'scope': scope_string,
        'response_type': 'code',
        'client_id': client_id,
        'state': 'statevalue',
      }
    data.update(custom or {})
    remove_empty_parameters(data)


    headers = {
        'wsgi.url_scheme': 'https' if use_ssl else 'http',
      }

    request_method = getattr(self, method.lower())
    api_request = request_method(endpoint, data, **headers)

    return api_request

  def make_api_request(self,
                       access_token,
                       data=None,
                       method='GET',
                       header_data=None,
                       meta=None,
                       use_ssl=True):


    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    request_method = getattr(RequestFactory(), method.lower())

    data = data or {}
    remove_empty_parameters(data)

    headers = {
        # From http://codeinthehole.com/writing/testing-https-handling-in-django/
        'wsgi.url_scheme': 'https' if use_ssl else 'http',
      }
    headers.update(header_data or {})
    remove_empty_parameters(headers)

    api_request = request_method('/url/does/not/matter', data, **headers)
    api_request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + access_token.value
    api_request.META.update(meta or {})
    remove_empty_parameters(api_request.META)

    return api_request

  def access_token_request(self,
                           client,
                           method,
                           data=None,
                           header_data=None,
                           use_header_auth=True,
                           use_ssl=None,
                           endpoint_uri=None):

    # Respect default ssl settings if no value is passed.
    if use_ssl is None:
      use_ssl = self.ssl_only

    params = {
        'client_id': client.key,
        'client_secret': client.secret,
        'redirect_uri': client.redirect_uri,
      }
    params.update(data or {})
    remove_empty_parameters(params)

    headers = {
        # From http://codeinthehole.com/writing/testing-https-handling-in-django/
        'wsgi.url_scheme': 'https' if use_ssl else 'http',
      }
    if use_header_auth:
      client_id = params.pop('client_id', '')
      client_secret = params.pop('client_secret', '')
      headers.update({'HTTP_AUTHORIZATION': 'Basic ' + b64encode(
        '{}:{}'.format(client_id, client_secret))})

    headers.update(header_data or {})
    remove_empty_parameters(headers)

    request_method = getattr(self, method.lower())

    response = request_method(
        endpoint_uri or self.token_endpoint,
        params,
        **headers)

    self.load_token_data(response)
    return response

  def request_token_from_authcode(self,
                                  client,
                                  authorization_code_value,
                                  method='POST',
                                  use_ssl=True,
                                  **kwargs):
    data = {
      'grant_type': 'authorization_code',
      'code': authorization_code_value,
    }
    data.update(kwargs.pop('data', {}))
    kwargs['data'] = data
    kwargs['use_ssl'] = use_ssl
    return self.access_token_request(client, method, **kwargs)

  def request_token_from_refresh_token(self,
                                  client,
                                  refresh_token_value,
                                  method='POST',
                                  use_ssl=True,
                                  **kwargs):
    data = {
      'grant_type': 'refresh_token',
      'refresh_token': refresh_token_value,
    }
    data.update(kwargs.pop('data', {}))
    kwargs['data'] = data
    kwargs['use_ssl'] = use_ssl
    return self.access_token_request(client, method, **kwargs)


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
  urls = 'djoauth2.tests.test_urls'
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

  def create_scope(self, custom=None):
    random_string = md5(str(random())).hexdigest()
    params = {
      'name' : 'test-scope-' + random_string,
      'description' : 'an example test scope',
    }
    params.update(custom or {})
    return Scope.objects.create(**params)

  def assert_token_success(self, response):
    self.assertEqual(response.status_code, 200, response)
    # Check the response contents
    self.assertTrue(self.oauth_client.access_token_value)
    self.assertTrue(self.oauth_client.access_token_lifetime)
    self.assertTrue(self.oauth_client.refresh_token_value)

  def assert_token_failure(self, response, expected_error_code=None):
    if expected_error_code:
      self.assertEqual(response.status_code, expected_error_code)
    else:
      # Should have received a 4XX HTTP status code
      self.assertNotEqual(response.status_code, 200, response)
      self.assertTrue(str(response.status_code)[0] == '4')
    # Check the response contents
    self.assertIsNone(self.oauth_client.access_token_value)
    self.assertIsNone(self.oauth_client.access_token_lifetime)
    self.assertIsNone(self.oauth_client.refresh_token_value)
