# coding: utf-8
import datetime

from django.conf import settings
from django.http import HttpResponse

from djoauth2.tests.abstractions import DJOAuth2TestCase
from djoauth2.decorators import oauth_scope
from djoauth2.models import AccessToken

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
  def test_ssl_only_ssl_request_succeeds(self):
    """ Test that secure requests succeed when the backend requires all
    AccessToken-authenticated requests to be secure, as recommended by
    http://tools.ietf.org/html/rfc6750#section-1 and
    http://tools.ietf.org/html/rfc6750#section-5.3 .
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_SSL_ONLY = True

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, use_ssl=True)

    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_ssl_only_insecure_request_fails(self):
    """ Test that insecure requests fail when the backend requires all
    AccessToken-authenticated requests to be secure, as recommended by
    http://tools.ietf.org/html/rfc6750#section-1 and
    http://tools.ietf.org/html/rfc6750#section-5.3 .
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_SSL_ONLY = True

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, use_ssl=False)

    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIsInstance(response, HttpResponse, response)
    self.assertEqual(response.status_code, 400, response.status_code)

  def test_no_ssl_required_ssl_request_succeeds(self):
    """ Test that secure requests succeed when the backend DOES NOT require
    AccessToken-authenticated requests to be secure.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_SSL_ONLY = False

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, use_ssl=True)

    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_no_ssl_required_insecure_request_succeeds(self):
    """ Test that insecure requests succeed when the backend DOES NOT require
    AccessToken-authenticated requests to be secure.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_SSL_ONLY = False

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(
        access_token, {}, use_ssl=False)

    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_missing_authentication_header_fails_without_error_information(self):
    """ If an API request is made without a WWW-Authenticate header containing
    an access token, it sould receive a response with status code 400 and no
    further error information.
    From http://tools.ietf.org/html/rfc6750#section-3.1 :

         If the request lacks any authentication information (e.g., the
         client was unaware that authentication is necessary or attempted
         using an unsupported authentication method), the resource server
         SHOULD NOT include an error code or other error information.

    """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})

    if 'HTTP_AUTHORIZATION' in api_request.META:
      del api_request.META['HTTP_AUTHORIZATION']

    self.assertNotIn('HTTP_AUTHORIZATION', api_request.META)

    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 400, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_non_bearer_authentication_header_fails_without_error_information(self):
    """ Only Bearer authentication is supported. If a Client tries to
    authenticate via any other method, the response should fail with status
    code of 400 and no futher error information, as recommended by
    http://tools.ietf.org/html/rfc6750#section-3.1 :

         If the request lacks any authentication information (e.g., the
         client was unaware that authentication is necessary or attempted
         using an unsupported authentication method), the resource server
         SHOULD NOT include an error code or other error information.

    """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_request.META['HTTP_AUTHORIZATION'] = 'NotBearer ' + access_token.value

    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 400, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_malformed_authentication_header_fails(self):
    """ API requests with malformed authentication headers cannot be
    authenticated correctly, and should fail.
    """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_request.META['HTTP_AUTHORIZATION'] = 'INVALID'

    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 400, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_nonexistent_access_token_fails(self):
    """ API requests that attempt to authenticate with nonexistent AccessTokens
    should fail.
    """
    """ API requests with malformed authentication headers cannot be
    authenticated correctly, and should fail.
    """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)
    access_token.delete()
    self.assertFalse(AccessToken.objects.filter(value=access_token.value).exists())

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + access_token.value

    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 401, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_expired_access_token_fails(self):
    """ If a request is made with an expired token, the endpoint should respond
    with status code 401. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)
    access_token.date_created -= datetime.timedelta(
        seconds=access_token.lifetime)
    access_token.save()

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_endpoint = make_oauth_protected_endpoint('verify')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 401, api_response)
    self.assertIn('WWW-Authenticate', api_response)

  def test_scope_equivalent_to_endpoint_scope_succeeds(self):
    """ A client with access to a given scope should have access to all
    API resources protected by that scope. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_scope_superset_of_endpoint_scope_succeeds(self):
    """ Requests from a Client with access to multiple scopes should succeed
    when made to an API resource protected by a subset of the Client's granted
    scopes.
    """
    self.initialize(scope_names=['verify', 'autologin'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_endpoint = make_oauth_protected_endpoint('verify')

    response = api_endpoint(api_request)
    self.assertIs(response, True, response)

  def test_scope_subset_of_endpoint_scope_fails(self):
    """ A client without access to the scope protecting an endpoint should
    receive a 403 error when making requests to said endpoint. """
    self.initialize(scope_names=['verify'])

    access_token = self.create_access_token(self.user, self.client)

    api_request = self.oauth_client.make_api_request(access_token, {})
    api_endpoint = make_oauth_protected_endpoint('verify', 'autologin')

    api_response = api_endpoint(api_request)
    self.assertEqual(api_response.status_code, 403, api_response)
    self.assertIn('WWW-Authenticate', api_response)



