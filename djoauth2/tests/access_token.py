# coding: utf-8
import datetime
import json
from base64 import b64encode

from django.conf import settings
from django.http import HttpRequest

from djoauth2.models import AccessToken
from djoauth2.models import AuthorizationCode
from djoauth2.models import Client
from djoauth2.models import Scope
from djoauth2.signals import refresh_token_used_after_invalidation
from djoauth2.tests.abstractions import DJOAuth2TestCase


class TestAccessTokenEndpoint(DJOAuth2TestCase):
  def test_ssl_required_insecure_request_fails(self):
    """ When SSL is required (as per spec), insecure requests should fail. """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = True

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_ssl=False)

    self.assert_token_failure(response, 400)

  def test_ssl_required_secure_request_succeeds(self):
    """ When SSL is required (as per spec), secure requests should succeed. """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = True

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_secure_request_succeeds(self):
    """ When SSL is NOT required (in violation of the spec), secure requests
    should still succeed.
    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_ssl=True)

    self.assert_token_success(response)

  def test_no_ssl_required_insecure_request_succeeds(self):
    """ When SSL is NOT required (in violation of the spec), insecure requests
    should succeed.
    """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_SSL_ONLY = False

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_ssl=True)

    self.assert_token_success(response)

  def test_get_requests_fail(self):
    """ The AccessToken endpoint should only accept POST requests. """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)
    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value, method='GET')

    self.assert_token_failure(response, 400)

  def test_put_requests_fail(self):
    """ The AccessToken endpoint should only accept POST requests. """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)
    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value, method='PUT')

    self.assert_token_failure(response, 400)

  def test_header_auth_succeeds(self):
    """ Clients should be able to successfully authenticate with HTTP Basic
    Authentication, as described by
    http://tools.ietf.org/html/rfc6749#section-2.3.1 .
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_header_auth=True)

    self.assert_token_success(response)

  def test_malformed_header_auth_fails(self):
    """ Requests attempting to authenticate with HTTP Basic Authentication
    using a malformed header should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        header_data={
          'HTTP_AUTHORIZATION': 'INVALID',
        },
        use_header_auth=True)

    self.assert_token_failure(response, 400)

  def test_header_auth_method_is_not_basic_fails(self):
    """ Requests attempting to authenticate with non-Basic HTTP Authentication
    should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        header_data={
          'HTTP_AUTHORIZATION': 'Bearer ' + b64encode(
            '{}:{}'.format(self.client.key, self.client.secret)),
        },
        use_header_auth=True)

    self.assert_token_failure(response, 400)

  def test_header_auth_value_is_malformed_fails(self):
    """ Clients attempting to authenticate with HTTP Basic Authentication ...
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        header_data={
          'HTTP_AUTHORIZATION': 'Basic ' + 'ThisIsInvalidBase64',
        },
        use_header_auth=True)

    self.assert_token_failure(response, 400)

  def test_including_authorization_in_request_uri_fails(self):
    """ Clients must not include authorization parameters in the request URI,
    as specified by http://tools.ietf.org/html/rfc6749#section-2.3.1 .
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_header_auth=True,
        endpoint_uri="{}?client_id={}&client_secret={}".format(
          self.oauth_client.token_endpoint,
          self.client.key,
          self.client.secret))

    self.assert_token_failure(response, 400)

  def test_body_auth_succeeds(self):
    """ Clients may include authorization details in the body of the POST request,
    as specified by http://tools.ietf.org/html/rfc6749#section-3.2.1 .
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_header_auth=False)

    self.assert_token_success(response)

  def test_multiple_types_of_authentication_fails(self):
    """ Clients must only use one authentication method in each request, as
    specified by http://tools.ietf.org/html/rfc6749#section-2.3 .
    """
    self.initialize(scope_names=['verify', 'autologin'])
    authcode = self.create_authorization_code(self.user, self.client)

    request_data = {
        'grant_type': 'authorization_code',
        'code': authcode.value,
        # Include authorzation values in the request body
        'client_id': self.client.key,
        'client_secret' : self.client.secret,
      }
    headers = {
        'wsgi.url_scheme': 'https' if self.oauth_client.ssl_only else 'http',
        # Include authorzation values in the request header
        'HTTP_AUTHORIZATION': 'Basic ' + b64encode(
          '{}:{}'.format(self.client.key, self.client.secret))}

    response = self.oauth_client.post(self.oauth_client.token_endpoint,
        request_data, **headers)
    self.assert_token_failure(response, 400)

  def test_nonexistent_client_fails(self):
    """ Requests that attempt to authenticate with a non-existent Client should
    fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    self.client.delete()
    self.assertFalse(
        Client.objects.filter(key=self.client.key).exists())

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        use_header_auth=False)

    self.assert_token_failure(response, 401)


  def test_missing_secret_fails(self):
    """ If the access token request does not include a secret, it should fail. """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          # Override default client_secret param to not exist.
          'client_secret' : None
        })

    self.assert_token_failure(response, 400)

  def test_mismatched_client_and_secret_fails(self):
    """ If the access token request includes a secret that doesn't match the
    registered secret, the request should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    # Override default client_secret param to not match the client's registered
    # secret.
    mismatched_secret = self.client.secret + 'thischangesthevalue'
    self.assertNotEqual(mismatched_secret, self.client.secret)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          'client_secret' : mismatched_secret
        },
        use_header_auth=True)

    self.assert_token_failure(response, 401)

  def test_invalid_grant_type_fails(self):
    """ If a request is made without a valid grant type, the request should
    fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          'grant_type': 'invalid'
        })

    self.assert_token_failure(response, 400)

  def test_omitted_grant_type_fails(self):
    """ If a request is made without a valid grant type, the request should
    fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          'grant_type': None,
        })

    self.assert_token_failure(response, 400)



class TestRequestAccessTokenFromAuthorizationCode(DJOAuth2TestCase):
  def test_request_without_code_value_fails(self):
    """ A request with a "grant_type" of "authorization_code" that does not
    also include a "code" parameter should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(
        self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client2,
        authcode.value,
        data={
          # Remove the code parameter from the request
          'code': None,
        })

    self.assert_token_failure(response, 400)

  def test_nonexistent_code_fails(self):
    """ An request based on a non-existent AuthorizationCode value should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(
        self.user, self.client)
    authcode.delete()
    self.assertFalse(
        AuthorizationCode.objects.filter(value=authcode.value).exists())

    response = self.oauth_client.request_token_from_authcode(
        self.client2, authcode.value)

    self.assert_token_failure(response, 400)

  def test_mismatched_code_and_client_fails(self):
    """ If the code authorized by a user is not associated with the OAuth
    client making the access token request, the request will fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    default_client_authcode = self.create_authorization_code(
        self.user, self.client)

    # Prove that the second OAuth client does not have the same key or secret
    # as the default OAuth client.
    self.assertNotEqual(default_client_authcode.client.key, self.client2.key)
    self.assertNotEqual(default_client_authcode.client.secret,
                        self.client2.secret)

    response = self.oauth_client.request_token_from_authcode(
        self.client2,
        default_client_authcode.value)

    self.assert_token_failure(response, 400)

  def test_expired_code_fails(self):
    """ If an authorization code is unused within its lifetime, an attempt to
    use it will fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    # Modify the authcode's date_created timestamp to be sufficiently far in
    # the past that it is now expired.
    authcode = self.create_authorization_code(self.user, self.client)
    authcode.date_created -= datetime.timedelta(seconds=authcode.lifetime)
    authcode.save()
    self.assertTrue(authcode.is_expired())

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)

    self.assert_token_failure(response, 400)

  def test_reuse_of_single_authorization_code_fails_and_invalidates_previously_granted_tokens(self):
    """ If an authorization code is used more than once, the authorization
    server MUST deny the request and SHOULD revoke (when possible) all tokens
    previously issued based on that authorization code.
    -- http://tools.ietf.org/html/rfc6749#section-4.1.2
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)
    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)
    self.assert_token_failure(response2, 400)

    authcode = AuthorizationCode.objects.get(pk=authcode.pk)
    for access_token in authcode.access_tokens.all():
      self.assertTrue(access_token.invalidated)

  def test_no_redirect_uri_passed_defaults_to_registered_and_succeeds(self):
    """ If the OAuth client has registered a redirect uri, it is OK to not
    explicitly pass the same URI again.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    # Create an authorization code without a redirect URI.
    authcode = self.create_authorization_code(self.user, self.client, {
        'redirect_uri' : None
      })

    # Override the default redirect param to not exist.
    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          'redirect_uri' : None,
        })

    self.assert_token_success(response)

  def test_passed_redirect_uri_matches_registered_and_succeeds(self):
    """ If the OAuth client has registered a redirect uri, and the same
    redirect URI is passed here, the request should succeed.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client, {
          'redirect_uri' : self.client.redirect_uri
        })

    # Request an authorization token with the same redirect as the
    # authorization code (the OAuth spec requires them to match.)
    response = self.oauth_client.request_token_from_authcode(
        self.client,
        authcode.value,
        data={
          'redirect_uri' : self.client.redirect_uri,
        })

    self.assert_token_success(response)

  def test_passed_redirect_uri_does_not_match_registered_uri_and_fails(self):
    """ If the OAuth client has registered a redirect uri, and passes a
    different redirect URI to the access token request, the request will fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

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
        data={
          'redirect_uri' : different_redirect,
        })

    self.assert_token_failure(response, 400)


  def test_after_success_authorization_code_is_invalidated(self):
    """ After successfully being exchanged for an AccessToken, an
    AuthorizationCode should be marked as 'invalidated' so that it cannot be
    used again.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    authcode = self.create_authorization_code(self.user, self.client)

    response = self.oauth_client.request_token_from_authcode(
        self.client, authcode.value)
    self.assert_token_success(response)
    authcode_in_db = AuthorizationCode.objects.get(pk=authcode.pk)
    self.assertTrue(authcode_in_db.invalidated)


class TestRequestAccessTokenFromRefreshToken(DJOAuth2TestCase):
  def test_request_without_refresh_token_value_fails(self):
    """ Requests with "grant_type" of "refresh_token" that do not include a
    "refresh_token" value should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])
    response = self.oauth_client.request_token_from_refresh_token(
        self.client, None)

    self.assert_token_failure(response, 400)

  def test_request_with_nonexistent_refresh_token_fails(self):
    """ Requests with "grant_type" of "refresh_token" that include a
    "refresh_token" value that does not exist should fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    refresh_token_value = 'doesnotexist'
    self.assertFalse(
        AccessToken.objects.filter(refresh_token=refresh_token_value).exists())

    response = self.oauth_client.request_token_from_refresh_token(
        self.client, refresh_token_value)

    self.assert_token_failure(response, 400)

  def test_request_with_mismatched_client_and_refresh_token_fails(self):
    """ One client may not refresh another client's AccessToken. """
    self.initialize(scope_names=['verify', 'autologin'])

    default_client_access_token = self.create_access_token(
        self.user, self.client)

    self.assertNotEqual(default_client_access_token.client.key,
                        self.client2.key)
    self.assertNotEqual(default_client_access_token.client.secret,
                        self.client2.secret)

    response = self.oauth_client.request_token_from_authcode(
        self.client2, default_client_access_token.value)

    self.assert_token_failure(response, 400)

  def test_reuse_of_refresh_token_fails(self):
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
        self.client, access_token_1.refresh_token)

    self.assert_token_success(response)

    response2 = self.oauth_client.request_token_from_refresh_token(
        self.client, access_token_1.refresh_token)

    self.assert_token_failure(response2, 400)

    existing_token_filter = AccessToken.objects.filter(
        refresh_token=access_token_1.refresh_token)

    self.assertTrue(existing_token_filter.exists())
    self.assertEqual(len(existing_token_filter), 1)
    self.assertEqual(existing_token_filter[0].pk, access_token_1.pk)
    self.assertTrue(existing_token_filter[0].invalidated)

  def test_reuse_of_refresh_token_fails_and_fires_signal(self):
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
        self.client, access_token.refresh_token)

    self.assert_token_failure(response, 400)
    self.assertTrue(self.received_signal)

  def test_tokens_not_refreshable_fails(self):
    """ Attempts to refresh non-rereshable tokens should fail. """
    self.initialize(scope_names=['verify', 'autologin'])
    settings.DJOAUTH2_ACCESS_TOKENS_REFRESHABLE = False

    access_token = self.create_access_token(self.user, self.client)
    self.assertFalse(access_token.refreshable)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client, access_token.refresh_token)

    self.assert_token_failure(response, 400)

  def test_request_with_no_scope_succeeds_with_scope_equivalent_to_original(self):
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
        data={
          'scope': None
        })

    self.assert_token_success(response)
    refresh_data = json.loads(response.content)
    self.assertEqual(refresh_data['scope'], self.oauth_client.scope_string)

  def test_request_with_same_scope_as_original_token_succeeds(self):
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
        data={
          'scope': scope_string_1,
        })

    self.assert_token_success(response)
    scope_string_2 = json.loads(response.content).get('scope')
    self.assertEqual(scope_string_1, scope_string_2)

  def test_request_with_subset_of_initial_scope_fails(self):
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
        data={
          'scope': ' '.join(scope_list_2),
        })

    self.assert_token_failure(response, 400)

  def test_request_with_superset_of_initial_scope_fails(self):
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
        data={
          'scope': ' '.join(scope_list_2),
        })

    self.assert_token_failure(response, 400)

  def test_request_with_nonexistent_scope_fails(self):
    """ Refresh requests that ask for access to non-existent Scopes should
    fail.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    non_existent_scope_name = 'dne'
    self.assertFalse(
        Scope.objects.filter(name=non_existent_scope_name).exists())

    response = self.oauth_client.request_token_from_refresh_token(
        self.client,
        access_token.refresh_token,
        data={
          'scope': non_existent_scope_name,
        })

    self.assert_token_failure(response, 400)

  def test_after_success_refresh_token_is_invalidated(self):
    """ After successfully being exchanged for an AccessToken, a refresh token
    should be marked as 'invalidated' so that it cannot be used again.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    response = self.oauth_client.request_token_from_refresh_token(
        self.client, access_token.refresh_token)
    self.assert_token_success(response)

    access_token_in_db = AccessToken.objects.get(pk=access_token.pk)
    self.assertTrue(access_token_in_db.invalidated)

