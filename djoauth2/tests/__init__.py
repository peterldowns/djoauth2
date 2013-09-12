# coding: utf-8
import datetime
import json
from hashlib import md5
from random import random

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client as TestClient
from django.test import TestCase
from django.test.client import RequestFactory

from djoauth2.decorators import oauth_scope
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
                           method='POST',
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

    request_method = getattr(self, method.lower())
    response = request_method(self.token_endpoint, data=data, **{
      # From http://codeinthehole.com/writing/testing-https-handling-in-django/
      'wsgi.url_scheme': 'https' if use_ssl else 'http'})
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


class TestAccessTokenFromAuthorizationCode(DJOAuth2TestCase):
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
    response = self.oauth_client.request_token_from_authcode(
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
    response = self.oauth_client.request_token_from_authcode(
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

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        custom={
          'redirect_uri' : different_redirect,
        })

    self.assert_token_failure(response)

  def test_insecure_request_fails(self):
    """ SSL is required when making requests to the access token endpoint. """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value, use_ssl=False)

    self.assert_token_failure(response)

  def test_missing_secret(self):
    """ If the access token request does not include a secret, it will fail. """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    # Override default client_secret param to not exist.
    response = self.oauth_client.request_token_from_authcode(
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

    response = self.oauth_client.request_token_from_authcode(
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

    response = self.oauth_client.request_token_from_authcode(
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

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)

    self.assert_token_failure(response)

  def test_multiple_use_of_single_authorization_code(self):
    """ If an authorization code is used more than once, the authorization
    server MUST deny the request and SHOULD revoke (when possible) all tokens
    previously issued based on that authorization code.
    -- http://tools.ietf.org/html/rfc6749#section-4.1.2
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)
    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)
    self.assert_token_failure(response2)

    authcode = AuthorizationCode.objects.get(pk=authcode.pk)
    for access_token in authcode.access_tokens.all():
      self.assertTrue(access_token.is_expired())

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

    response = self.oauth_client.request_token_from_authcode(
        self.client, fake_authcode_value)

    self.assert_token_failure(response)

  def test_get_requests_fail(self):
    """ The Access Token endpoint should not accept GET requests -- only POST.
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)
    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value, method='GET')

    self.assert_token_failure(response)


class TestAccessTokenFromRefreshToken(DJOAuth2TestCase):
  def test_tokens_not_refreshable_fails(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = False

    access_token = self.create_access_token(self.user, self.client)
    self.assertFalse(access_token.refreshable)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client, access_token.refresh_token)

    self.assert_token_failure(response)


  def test_request_with_no_scope_succeeds(self):
    """ If an OAuth client makes a refresh token request without specifying the
    scope, the client should receive a token with the same scopes as the
    original.

    Also, I was *this* close to naming this method
    "test_xXxXx420HEADSHOT_noscope_SWAGYOLOxXxXx".
    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token = self.create_access_token(self.user, self.client)

    response2 = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        custom={
          'scope': None
        })

    self.assert_token_success(response2)
    refresh_data = json.loads(response2.content)
    self.assertEqual(refresh_data['scope'], self.oauth_client.scope_string)

  def test_request_with_same_scope_succeeds(self):
    """ A request for a new AccessToken made with a RefreshToken that includes
    a scope parameter for the same scope as the existing
    RefreshToken/AccessToken pair should succeed.
    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string


    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        custom={
          'scope': scope_string_1,
        })

    self.assert_token_success(response)
    scope_string_2 = json.loads(response.content).get('scope')
    self.assertEqual(scope_string_1, scope_string_2)

  def test_request_with_subset_of_initial_scope(self):
    """ If a new refresh token is issued, the refresh token scope MUST be
    identical to that of the refresh token included by the client in the
    request. -- http://tools.ietf.org/html/rfc6749#section-6
    """
    scope_list_1 = ['verify', 'autologin']
    self.initialize(scope_names=scope_list_1)
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string

    scope_list_2 = scope_list_1[:1]
    self.assertGreater(set(scope_list_1), set(scope_list_2))

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        custom={
          'scope': ' '.join(scope_list_2),
        })

    self.assert_token_failure(response)

  def test_request_with_superset_of_initial_scope(self):
    """ If a new refresh token is issued, the refresh token scope MUST be
    identical to that of the refresh token included by the client in the
    request. -- http://tools.ietf.org/html/rfc6749#section-6
    """
    scope_list_1 = ['verify', 'autologin']
    self.initialize(scope_names=scope_list_1)
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string

    scope_list_2 = scope_list_1 + ['example']
    self.assertGreater(set(scope_list_2), set(scope_list_1))

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        custom={
          'scope': ' '.join(scope_list_2),
        })

    self.assert_token_failure(response)

  def test_request_with_nonexistent_refresh_token_(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    refresh_token_value = 'doesnotexist'
    self.assertFalse(
        AccessToken.objects.filter(refresh_token=refresh_token_value).exists())

    response = self.oauth_client.request_token_from_refresh_token(
        self.client, refresh_token_value)

    self.assert_token_failure(response)

  def test_request_with_invalid_grant_type(self):
    """ RefreshToken-based requests for new AccessTokens that specify a
    "grant_type" parameter that isn't "refresh_token" will fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        custom={
          'grant_type': 'not_refresh_token',
        })

    self.assert_token_failure(response)

  def test_request_with_mismatched_client(self):
    """ One client ay not refresh another client's token. """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    default_client_access_token = self.create_access_token(
        self.user, self.client)

    self.assertNotEqual(default_client_access_token.client.key,
                        self.client2.key)
    self.assertNotEqual(default_client_access_token.client.secret,
                        self.client2.secret)

    response = self.oauth_client.request_token_from_authcode(
        self.client2, default_client_access_token.value)

    self.assert_token_failure(response)

  def test_multiple_access_same_token(self):
    """ Each refresh token can only be used once. Attempting to refresh with a
    token that has already been used will result in a failure.

    From http://tools.ietf.org/html/rfc6749#section-10.4 :

        The authorization server MUST verify the binding between the refresh
        token and client identity whenever the client identity can be
        authenticated. For example, the authorization server could employ
        refresh token rotation in which a new refresh token is issued with
        every access token refresh response.  The previous refresh token is
        invalidated but retained by the authorization server.

    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = True

    access_token_1 = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token)

    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token)

    self.assert_token_failure(response2)

    existing_token_filter = AccessToken.objects.filter(
        refresh_token=access_token_1.refresh_token)

    self.assertTrue(existing_token_filter.exists())
    self.assertEqual(len(existing_token_filter), 1)
    self.assertEqual(existing_token_filter[0].pk, access_token_1.pk)
    self.assertTrue(existing_token_filter[0].invalidated)



def make_oauth_protected_endpoint(*args, **kwargs):
  """ Returns a dummy API endpoint that returns True. This endpoint will be
  protected with the @oauth_scope decorator -- see that function's signature
  for a description of the parameters that may be passed. """
  @oauth_scope(*args, **kwargs)
  def api_endpoint(access_token, request):
    """ A Dummy API endpoint that accepts no URL parameters.

    Always returns True.
    """
    return True

  return api_endpoint


class TestOAuthScopeEndpointDecorator(DJOAuth2TestCase):
  def test_scope_same(self):
    """ A client with access to a given scope should have access to all
    endpoints protected with that scope. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, 'GET')
    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_scope_superset(self):
    """ A client with multiple scopes sould have access to all endpoints
    protected with a subset of those scopes. """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, 'GET')
    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_scope_subset(self):
    """ A client without access to the scope protecting an endpoint should
    receive a 403 error when making requests to said endpoint. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, 'GET')
    api_endpoint = make_oauth_protected_endpoint('verify', 'autologin')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 403, api_response)
    self.assertIn('WWW-Authenticate', api_response)


  def test_expired_access_token(self):
    """ If a request is made with an expired token, the endpoint should respond
    with status code 401. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)
    access_token.date_created -= datetime.timedelta(
        seconds=access_token.lifetime)
    access_token.save()

    api_request = self.oauth_client.make_api_request(
        access_token, {}, 'GET')
    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 401, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_missing_authentication_header(self):
    """ If an API request is made without a WWW-Authenticate header containing
    an access token, it sould receive a response with status code 400. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, 'GET')

    if 'HTTP_AUTHORIZATION' in api_request.META:
      del api_request.META['HTTP_AUTHORIZATION']

    self.assertNotIn('HTTP_AUTHORIZATION', api_request.META)

    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 400, api_response)
    self.assertIn('WWW-Authenticate', api_response)

