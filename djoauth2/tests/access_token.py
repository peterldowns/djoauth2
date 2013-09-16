# coding: utf-8
import datetime
import json

from django.conf import settings
from django.http import HttpRequest

from djoauth2.models import AccessToken
from djoauth2.models import AuthorizationCode
from djoauth2.signals import refresh_token_used_after_invalidation
from djoauth2.tests.abstractions import DJOAuth2TestCase

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
        method='POST',
        data={
          'redirect_uri' : None,
        },
        use_ssl=True)

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
        method='POST',
        data={
          'redirect_uri' : self.client.redirect_uri,
        },
        use_ssl=True)

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
        method='POST',
        data={
          'redirect_uri' : different_redirect,
        },
        use_ssl=True)

    self.assert_token_failure(response)

  def test_ssl_required_insecure_request_fails(self):
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = True

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        use_ssl=False)

    self.assert_token_failure(response)

  def test_ssl_required_secure_request_succeeds(self):
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = True

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_secure_request_succeeds(self):
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_insecure_request_succeeds(self):
    self.initialize()
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

  def test_missing_secret(self):
    """ If the access token request does not include a secret, it will fail. """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)

    # Override default client_secret param to not exist.
    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        data={
          'client_secret' : None
        },
        header_data={
          'client_secret' : None
        },
        use_ssl=True)

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
        method='POST',
        data={
          'client_secret' : mismatched_secret
        },
        use_ssl=True)

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
        self.client2,
        default_client_authcode.value,
        method='POST',
        use_ssl=True)

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
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)

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
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)
    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='POST',
        use_ssl=True)
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
        self.client,
        fake_authcode_value,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response)

  def test_get_requests_fail(self):
    """ The Access Token endpoint should not accept GET requests -- only POST.
    """
    self.initialize()

    authcode = self.create_authorization_code(self.user, self.client)
    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        method='GET',
        use_ssl=True)

    self.assert_token_failure(response)


class TestAccessTokenFromRefreshToken(DJOAuth2TestCase):
  def test_tokens_not_refreshable_fails(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = False

    access_token = self.create_access_token(self.user, self.client)
    self.assertFalse(access_token.refreshable)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response)


  def test_request_with_no_scope_succeeds(self):
    """ If an OAuth client makes a refresh token request without specifying the
    scope, the client should receive a token with the same scopes as the
    original.

    Also, I was *this* close to naming this method
    "test_xXxXx420HEADSHOT_noscope_SWAGYOLOxXxXx".
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        data={
          'scope': None
        },
        use_ssl=True)

    self.assert_token_success(response)
    refresh_data = json.loads(response.content)
    self.assertEqual(refresh_data['scope'], self.oauth_client.scope_string)

  def test_request_with_same_scope_succeeds(self):
    """ A request for a new AccessToken made with a RefreshToken that includes
    a scope parameter for the same scope as the existing
    RefreshToken/AccessToken pair should succeed.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string


    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        method='POST',
        data={
          'scope': scope_string_1,
        },
        use_ssl=True)

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

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string

    scope_list_2 = scope_list_1[:1]
    self.assertGreater(set(scope_list_1), set(scope_list_2))

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        method='POST',
        data={
          'scope': ' '.join(scope_list_2),
        },
        use_ssl=True)

    self.assert_token_failure(response)

  def test_request_with_superset_of_initial_scope(self):
    """ If a new refresh token is issued, the refresh token scope MUST be
    identical to that of the refresh token included by the client in the
    request. -- http://tools.ietf.org/html/rfc6749#section-6
    """
    scope_list_1 = ['verify', 'autologin']
    self.initialize(scope_names=scope_list_1)

    access_token_1 = self.create_access_token(self.user, self.client)
    scope_string_1 = self.oauth_client.scope_string

    scope_list_2 = scope_list_1 + ['example']
    self.assertGreater(set(scope_list_2), set(scope_list_1))

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        method='POST',
        data={
          'scope': ' '.join(scope_list_2),
        },
        use_ssl=True)

    self.assert_token_failure(response)

  def test_request_with_nonexistent_refresh_token_(self):
    self.initialize(scope_names=['verify', 'autologin'])

    refresh_token_value = 'doesnotexist'
    self.assertFalse(
        AccessToken.objects.filter(refresh_token=refresh_token_value).exists())

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        refresh_token_value,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response)

  def test_request_with_invalid_grant_type(self):
    """ RefreshToken-based requests for new AccessTokens that specify a
    "grant_type" parameter that isn't "refresh_token" will fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        data={
          'grant_type': 'not_refresh_token',
        },
        use_ssl=True)

    self.assert_token_failure(response)

  def test_request_with_mismatched_client(self):
    """ One client ay not refresh another client's token. """
    self.initialize(scope_names=['verify', 'autologin'])

    default_client_access_token = self.create_access_token(
        self.user, self.client)

    self.assertNotEqual(default_client_access_token.client.key,
                        self.client2.key)
    self.assertNotEqual(default_client_access_token.client.secret,
                        self.client2.secret)

    response = self.oauth_client.request_token_from_authcode(
        self.client2,
        default_client_access_token.value,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response)

  def test_multiple_use_of_refresh_token(self):
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

    access_token_1 = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token_1.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response2)

    existing_token_filter = AccessToken.objects.filter(
        refresh_token=access_token_1.refresh_token)

    self.assertTrue(existing_token_filter.exists())
    self.assertEqual(len(existing_token_filter), 1)
    self.assertEqual(existing_token_filter[0].pk, access_token_1.pk)
    self.assertTrue(existing_token_filter[0].invalidated)

  def test_multiple_use_of_refresh_token_fires_signal(self):
    """ Our implementation should fire a
    'refresh_token_used_after_invalidation' signal that users may listen to and
    use to alert Clients that their refresh tokens have been accessed more than
    once. This is as recommendd by
    http://tools.ietf.org/html/rfc6749#section-10.4 :

         If a refresh token is compromised and subsequently used by both the
         attacker and the legitimate client, one of them will present an
         invalidated refresh token, which will inform the authorization server
         of the breach.

    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)
    access_token.invalidate()
    self.assertTrue(access_token.invalidated)

    self.received_signal = False

    def invalidated_refresh_token_use_callback(signal,
                                               sender,
                                               access_token,
                                               request):
      self.assertEqual(access_token.pk, access_token.pk)
      self.assertIsInstance(request, HttpRequest)
      self.received_signal = True

    refresh_token_used_after_invalidation.connect(
        invalidated_refresh_token_use_callback)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_failure(response)
    self.assertTrue(self.received_signal)

  def test_ssl_required_insecure_request_fails(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = True

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=False)

    self.assert_token_failure(response)

  def test_ssl_required_secure_request_succeeds(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = True

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_secure_request_succeeds(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = False

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_insecure_request_succeeds(self):
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = False

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        method='POST',
        use_ssl=False)

    self.assert_token_success(response)
