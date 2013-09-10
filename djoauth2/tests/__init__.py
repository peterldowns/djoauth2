# coding: utf-8
import datetime
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

    # For internal use
    self.history = []
    self.access_token = None
    self.refresh_token = None
    self.lifetime = None
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

    request_method = getattr(self, method.lower())
    response = request_method(self.token_endpoint, data=data, **{
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
    self.assertIsNone(self.oauth_client.lifetime)


class TestAccessToken(DJOAuth2TestCase):
  def test_pass_no_redirect_defaults_to_registered(self):
    """ If the OAuth client has registered a redirect uri, it is OK to not
    explicitly pass the same URI again.
    """
    self.initialize()

    # Create an authorization code without a redirect URI.
    authcode = self.create_authorization_code(self.user, self.client, {
        'redirect_uri' : None
      })

    # Override the default redirect param to not exist.
    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'redirect_uri' : None,
        })

    self.assert_token_success(response)

  def test_passed_uri_must_match_registered(self):
    """ If the OAuth client has registered a redirect uri, and the same
    redirect URI is passed here, the request should succeed.
    """
    self.initialize()

    # Create an authorization code, which must have a redirect because there is
    # no default redirect for this client
    authcode = self.create_authorization_code(self.user, self.client, {
          'redirect_uri' : self.client.redirect_uri
        })

    # Request an authorization token with the same redirect as the
    # authorization code (the OAuth spec requires them to match.)
    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'redirect_uri' : self.client.redirect_uri,
        })

    self.assert_token_success(response)

  def test_redirect_uri_does_not_match_registered_uri(self):
    """ If the OAuth client has registered a redirect uri, and passes a
    different redirect URI to the access token request, the request will fail.
    """
    self.initialize()

    # Request an authorization token with a redirect that is different than the
    # one registered by the client.

    authcode = self.create_authorization_code(self.user, self.client, {
          'redirect_uri' : self.client.redirect_uri
        })

    different_redirect = 'https://NOTlocu.com'
    self.assertNotEqual(different_redirect, self.client.redirect_uri)

    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'redirect_uri' : different_redirect,
        })

    self.assert_token_failure(response)

  def test_secure_request_succeeds_when_ssl_not_required(self):
    """ If the OAuth client has registered a secure redirect uri, and SSL is
    not required by the server, then requests will still succeed.
    """
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_access_token(
        self.client, authcode.value, use_ssl=True)

    self.assert_token_success(response)

  def test_insecure_request_succeeds_when_ssl_not_required(self):
    """ If the OAuth client has registered an insecure redirect uri, and
    SSL is not required by the server, then requests will succeed.
    """
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_access_token(
        self.client, authcode.value, use_ssl=False)

    self.assert_token_success(response)

  def test_insecure_request_fails_when_ssl_required(self):
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = True

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_access_token(
        self.client, authcode.value, use_ssl=False)

    self.assert_token_failure(response)

  def test_missing_secret(self):
    """ If the access token request does not include a secret, it will fail. """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    # Override default client_secret param to not exist.
    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'client_secret' : None
        })

    self.assert_token_failure(response)

  def test_mismatched_secret(self):
    """ If the access token request includes a secret that doesn't match the
    registered secret, the request will fail.
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    # Override default client_secret param to not match the client's registered
    # secret.
    mismatched_secret = self.client.secret + 'thischangesthevalue'
    self.assertNotEqual(mismatched_secret, self.client.secret)

    response = self.oauth_client.request_access_token(
        self.client,
        authcode.value,
        custom={
          'client_secret' : mismatched_secret
        })

    self.assert_token_failure(response)

  def test_mismatched_code_and_client(self):
    """ If the code authorized by a user is not associated with the OAuth
    client making the access token request, the request will fail.
    """
    self.initialize()

    default_client_authcode = self.create_authorization_code(
        self.user, self.client)

    # Prove that the second OAuth client does not have the same key or secret
    # as the default OAuth client.
    self.assertNotEqual(default_client_authcode.client.key, self.client2.key)
    self.assertNotEqual(default_client_authcode.client.secret,
                        self.client2.secret)

    response = self.oauth_client.request_access_token(
        self.client2, default_client_authcode.value)

    self.assert_token_failure(response)

  def test_expired_code(self):
    """ If an authorization code is unused within its lifetime, an attempt to
    use it will fail.
    """
    self.initialize()

    # Modify the authcode's date_created timestamp to be sufficiently far in
    # the past that it is now expired.
    authcode = self.create_authorization_code(self.user, self.client)
    authcode.date_created -= datetime.timedelta(seconds=authcode.lifetime)
    authcode.save()
    self.assertTrue(authcode.is_expired())

    response = self.oauth_client.request_access_token(
        self.client, authcode.value)

    self.assert_token_failure(response)

  def test_invalid_grant(self):
    """ If an Authorization Code / Grant does not exist, then the request will
    fail.
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)
    fake_authcode_value = "myfakeauthcodelol"
    self.assertNotEqual(authcode, fake_authcode_value)
    self.assertFalse(
        AuthorizationCode.objects.filter(value=fake_authcode_value).exists())

    response = self.oauth_client.request_access_token(
        self.client, fake_authcode_value)

    self.assert_token_failure(response)

  def test_get_requests_fail(self):
    """ The Access Token endpoint should not accept GET requests -- only POST.
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)
    response = self.oauth_client.request_access_token(
        self.client, authcode.value, method='GET')

    self.assert_token_failure(response)

