# coding: utf-8
import sys
from urlparse import urlparse
from urlparse import parse_qsl
from urlparse import urlunparse

from django.conf import settings
from django.conf.urls.defaults import patterns
from django.http import HttpResponse
from django.utils.importlib import import_module

from djoauth2.authorization import AuthorizationCodeGenerator
from djoauth2.authorization import AuthorizationException
from djoauth2.authorization import InvalidRequest
from djoauth2.authorization import InvalidScope
from djoauth2.authorization import UnauthenticatedUser
from djoauth2.authorization import UnsupportedResponseType
from djoauth2.helpers import update_parameters
from djoauth2.models import Scope
from djoauth2.models import Client
from djoauth2.tests import test_urls
from djoauth2.tests.abstractions import DJOAuth2TestCase



def make_validation_endpoint(endpoint_url, authorizer):
  """ Returns a dummy endpoint that validates a request and returns 'OK'.

  Also installs the endpoint to the global URLconf at the requested
  endpoint_url.
  """
  def authorization_endpoint(request):
    authorizer.validate(request)
    return HttpResponse('OK')

  # Reload the default URLs so that the temporary endpoint does not remain in
  # the URLconf from test to test.  Taken from
  # http://codeinthehole.com/writing/how-to-reload-djangos-url-config/ .
  if settings.ROOT_URLCONF in sys.modules:
    reload(sys.modules[settings.ROOT_URLCONF])

  urlpatterns = import_module(settings.ROOT_URLCONF).urlpatterns

  # Remove preceding slash for the URLconf endpoint regex.
  if endpoint_url[0] == '/':
    endpoint_url = endpoint_url[1:]

  # Add the temporary endpoint to the URLconf at the specified url.
  urlpatterns += patterns('',
      (r'^{}'.format(endpoint_url), authorization_endpoint),
  )

  return authorization_endpoint


class TestAuthorizationCodeEndpoint(DJOAuth2TestCase):
  missing_redirect_uri = '/oauth2/missing_redirect_uri/'
  dummy_endpoint_uri = '/oauth2/authorization/'

  def test_get_requests_succeed(self):
    """ The authorization server MUST suport the use of the HTTP "GET" method
    for the authorization endpoint.

    See http://tools.ietf.org/html/rfc6749#section-3.1 .
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        method='GET')

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_post_requests_succeed(self):
    """ [The authorization server] MAY suport the use of the HTTP "POST" method
    [for the authorization endpoint] as well.

    See http://tools.ietf.org/html/rfc6749#section-3.1 .
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        method='POST')

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_ssl_required_secure_request_succeeds(self):
    """ When SSL is required (as per spec), secure requests should succeed. """
    settings.DJOAUTH2_SSL_ONLY = True
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=True)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_ssl_required_insecure_request_fails(self):
    """ When SSL is required (as per spec), insecure requests should fail. """
    settings.DJOAUTH2_SSL_ONLY = True
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    with self.assertRaises(InvalidRequest):
      self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri,
          use_ssl=False)

  def test_no_ssl_required_secure_request_succeeds(self):
    """ When SSL is NOT required (in violation of the spec), secure requests
    should still fail. """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=True)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_no_ssl_required_insecure_request_succeeds(self):
    """ When SSL is NOT required (in violation of the spec), insecure requests
    should succeed. """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=False)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_user_not_authenticated_fails(self):
    """ The Authorization endpoint requires a logged-in user to accept or deny
    the request. If the user is not logged in, request can not be granted, and
    the request should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.logout()
    self.assertNotIn(settings.SESSION_COOKIE_NAME, self.oauth_client.cookies)

    with self.assertRaises(UnauthenticatedUser):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

  def test_response_type_not_code_fails(self):
    """ The implementation only supports the "code" "response_type" -- any
    other "response_type" parameter should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    with self.assertRaises(UnsupportedResponseType):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'response_type': 'not_code'
          },
          endpoint=self.dummy_endpoint_uri)

  def test_state_required_and_no_state_included_fails(self):
    """ When the "state" parameter is required (as recommended by the spec),
    requests that omit the parameter should fail.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = True

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'state': None,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_state_required_and_state_included_succeeds(self):
    """ When the "state" parameter is required (as recommended by the spec),
    requests that include the parameter should succeed.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = True

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'state': 'astatevalue',
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_state_not_requred_and_state_included_succeeds(self):
    """ When the "state" parameter is NOT required (against the recommendations
    of the spec), requests that include the parameter should still succeed.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = False

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'state': 'astatevalue',
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_state_not_requred_and_no_state_included_succeeds(self):
    """ When the "state" parameter is NOT required (against the recommendations
    of the spec), requests that omit the parameter should succeed.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = False

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'state': None,
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_state_included_on_success_redirect(self):
    """ When the "state" parameter is included, it must be preserved EXACTLY in
    the successful redirect response.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = False

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    # Store a state value to use in the request and for later comparison
    state_value = 'superstatevalue'

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'state': state_value,
        },
        endpoint=self.dummy_endpoint_uri)

    successful_redirect = auth_code_generator.make_success_redirect()

    # Grab the URL parameters from the redirect response's Location header and
    # turn them into a dict object.
    parsed_url_parameters = dict(
        parse_qsl(urlparse(successful_redirect.get('location')).query))

    self.assertIn('state', parsed_url_parameters)
    self.assertEqual(parsed_url_parameters['state'], state_value)

  def test_state_included_on_error_redirect(self):
    """ When the "state" parameter is included, it must be preserved EXACTLY in
    the error redirect response.
    """
    self.initialize(scope_names=['verify'])
    settings.DJOAUTH2_REQUIRE_STATE = False

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    # Store a state value to use in the request and for later comparison
    state_value = 'superstatevalue'

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'state': state_value,
        },
        endpoint=self.dummy_endpoint_uri)

    error_redirect = auth_code_generator.make_error_redirect()

    # Grab the URL parameters from the redirect response's Location header and
    # turn them into a dict object.
    parsed_url_parameters = dict(
        parse_qsl(urlparse(error_redirect.get('location')).query))

    self.assertIn('state', parsed_url_parameters)
    self.assertEqual(parsed_url_parameters['state'], state_value)

  def test_no_scope_included_fails(self):
    """ Authorization requests that do not include a "scope" parameter should
    fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'scope': None,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_nonexistent_scope_included_fails(self):
    """ Authorization requests that request access to non-existent Scopes
    should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    nonexistent_scope_name = 'dne'
    self.assertFalse(
        Scope.objects.filter(name=nonexistent_scope_name).exists())

    with self.assertRaises(InvalidScope):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'scope': nonexistent_scope_name,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_single_scope_included_succeeds(self):
    """ Authorization requests that request access to a single Scope should
    succeed.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'scope': 'verify',
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_multiple_scopes_included_succeeds(self):
    """ Authorization requests that request access to multiple Scopes should
    succeed.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'scope': 'verify autologin',
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_no_client_id_included_fails(self):
    """ Authorization requests must include a "client_id" parameter; if they
    do not, they should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'client_id': None,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_nonexistent_client_id_fails(self):
    """ Authorization requests that include a non-existentn "client_id"
    parameter should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    nonexistent_client_id = 'doesnotexist'
    self.assertFalse(
        Client.objects.filter(key=nonexistent_client_id).exists())

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'client_id': nonexistent_client_id,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_included_redirect_matches_registered_succeeds(self):
    """ If the request includes a "redirect_uri" parameter, it must match the
    registered value. If it does match, the request should succeed.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        custom={
          'redirect_uri': self.client.redirect_uri,
        },
        endpoint=self.dummy_endpoint_uri)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_included_redirect_does_not_match_registered_fails(self):
    """ If the request includes a "redirect_uri" parameter, it must match the
    registered value. If it does not match, the request should fail.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    different_redirect_uri = 'https://peterdowns.com'
    self.assertNotEqual(different_redirect_uri, self.client.redirect_uri)

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          custom={
            'redirect_uri': different_redirect_uri,
          },
          endpoint=self.dummy_endpoint_uri)

  def test_non_absolute_redirect_uri_fails(self):
    """ The redirection endpoint URI MUST be an absolute URI.

    See http://tools.ietf.org/html/rfc6749#section-3.1.2 .
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = '/relative/url/'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

  def test_redirect_uri_with_fragment_fails(self):
    """ The redirection endpoint URI MUST not include a fragment component.

    See http://tools.ietf.org/html/rfc6749#section-3.1.2 .
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'https://locu.com/#fragmentValue'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

  def test_ssl_required_secure_redirect_uri_succeeds(self):
    """ When SSL is required (as suggested by the spec), secure requests should
    succeed.
    """
    settings.DJOAUTH2_SSL_ONLY = True
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'https://locu.com'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=True)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_ssl_required_insecure_redirect_uri_fails(self):
    """ When SSL is required (as suggested by the spec), insecure requests should
    fail.
    """
    settings.DJOAUTH2_SSL_ONLY = True
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'http://locu.com'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri,
          use_ssl=True)


  def test_no_ssl_required_secure_redirect_uri_succeeds(self):
    """ When SSL is NOT required (against the recommendations of the spec),
    secure requests should still succeed.
    """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'https://locu.com'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=True)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_no_ssl_required_insecure_redirect_uri_succeeds(self):
    """ When SSL is NOT required (against the recommendations of the spec),
    secure requests should still succeed.
    """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)
    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'http://locu.com'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri,
        use_ssl=True)

    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.content, 'OK')

  def test_redirect_uri_query_parameters_preserved_on_success(self):
    """ Redirection endpoint URIs MAY include a query component, which MUST be
    retained when adding additional query parameters, such as during the
    success redirect.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    parameters_dict = {
        'value1': 'True',
        'value2': '4242424242',
        'foo': 'bar',
      }
    self.client.redirect_uri = update_parameters('https://locu.com/',
                                                 parameters_dict)
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    successful_redirect = auth_code_generator.make_success_redirect()

    # Grab the URL parameters from the redirect response's Location header and
    # turn them into a dict object.
    parsed_url_parameters = dict(
        parse_qsl(urlparse(successful_redirect.get('location')).query))

    for parameter, value in parameters_dict.iteritems():
      self.assertIn(parameter, parsed_url_parameters)
      self.assertEqual(parsed_url_parameters[parameter], value)

  def test_redirect_uri_query_parameters_preserved_on_error(self):
    """ Redirection endpoint URIs MAY include a query component, which MUST be
    retained when adding additional query parameters, such as during the
    error redirect.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    parameters_dict = {
        'value1': 'True',
        'value2': '4242424242',
        'foo': 'bar',
      }
    self.client.redirect_uri = update_parameters('https://locu.com/',
                                                 parameters_dict)
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    successful_redirect = auth_code_generator.make_error_redirect()

    # Grab the URL parameters from the redirect response's Location header and
    # turn them into a dict object.
    parsed_url_parameters = dict(
        parse_qsl(urlparse(successful_redirect.get('location')).query))

    for parameter, value in parameters_dict.iteritems():
      self.assertIn(parameter, parsed_url_parameters)
      self.assertEqual(parsed_url_parameters[parameter], value)

  def test_error_response_redirects_to_valid_uri(self):
    """ When a registered redirect URI is valid, the error redirect should
    direct the user to the registered URI.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    # This redirect_uri is absolute and secure -- therefore, valid.
    self.client.redirect_uri = 'https://locu.com/'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    # Even though the request was successful, create an error redirect.
    error_redirect = auth_code_generator.make_error_redirect()

    # Show that the error redirect was directed to the valid, registered URI
    # and not the default URI to use when the registered URI is invalid or
    # missing. Do not check query parameters (subject of another test.)
    parsed_redirect_uri = urlparse(error_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.client.redirect_uri)
    self.assertNotEqual(redirect_location, self.missing_redirect_uri)

  def test_success_response_redirects_to_valid_uri(self):
    """ When a registered redirect URI is valid, the success redirect should
    direct the user to the registered URI.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    # This redirect_uri is absolute and secure -- therefore, valid.
    self.client.redirect_uri = 'https://locu.com/'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    success_redirect = auth_code_generator.make_success_redirect()

    # Show that the error redirect was directed to the valid, registered URI
    # and not the default URI to use when the registered URI is invalid or
    # missing. Do not check query parameters (subject of another test.)
    parsed_redirect_uri = urlparse(success_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.client.redirect_uri)
    self.assertNotEqual(redirect_location, self.missing_redirect_uri)

  def test_error_response_does_not_redirect_to_non_absolute_uri(self):
    """ When a redirect URI is invalid, error responses should instead redirect
    to the registered missing redirect URI endpoint.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    # This redirect_uri is now NOT absolute, in violation of the spec.
    self.client.redirect_uri = '/relative/uri/'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

    error_redirect = auth_code_generator.make_error_redirect()

    # Show that the error redirect was directed to the default missing redirect
    # URI, and not the registered, and invalid, URI.
    parsed_redirect_uri = urlparse(error_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.missing_redirect_uri)
    self.assertNotEqual(redirect_location, self.client.redirect_uri)

  def test_error_response_does_not_redirect_to_uri_with_fragment(self):
    """ When a redirect URI is invalid, error responses should instead redirect
    to the registered missing redirect URI endpoint.
    """
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'https://locu.com/#fragmentValue'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

    error_redirect = auth_code_generator.make_error_redirect()

    # Show that the error redirect was directed to the default missing redirect
    # URI, and not the registered, and invalid, URI.
    parsed_redirect_uri = urlparse(error_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.missing_redirect_uri)
    self.assertNotEqual(redirect_location, self.client.redirect_uri)

  def test_error_response_does_not_redirect_to_insecure_redirect_uri_when_ssl_required(self):
    """ When SSL is required, error redirect responses should NOT direct the
    user to insecure endpoints, and instead use the missing URI redirect.
    """
    settings.DJOAUTH2_SSL_ONLY = True
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'http://locu.com/'
    self.client.save()

    with self.assertRaises(InvalidRequest):
      response = self.oauth_client.make_authorization_request(
          client_id=self.client.key,
          scope_string=self.oauth_client.scope_string,
          endpoint=self.dummy_endpoint_uri)

    error_redirect = auth_code_generator.make_error_redirect()

    parsed_redirect_uri = urlparse(error_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.missing_redirect_uri)
    self.assertNotEqual(redirect_location, self.client.redirect_uri)

  def test_error_response_does_redirect_to_insecure_redirect_uri_when_no_ssl_required(self):
    """ When no SSL is required, error redirect responses should successfully
    direct direct the user to insecure endpoints.
    """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'http://locu.com/'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    error_redirect = auth_code_generator.make_error_redirect()

    parsed_redirect_uri = urlparse(error_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.client.redirect_uri)
    self.assertNotEqual(redirect_location, self.missing_redirect_uri)

  def test_success_response_redirects_to_secure_uri_when_no_ssl_required(self):
    """ When no SSL is required, successful redirect responses should still
    direct the user to secure endpoints.
    """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'https://locu.com/'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    success_redirect = auth_code_generator.make_success_redirect()

    parsed_redirect_uri = urlparse(success_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.client.redirect_uri)
    self.assertNotEqual(redirect_location, self.missing_redirect_uri)

  def test_success_response_redirects_to_insecure_uri_when_no_ssl_required(self):
    """ When no SSL is required, successful redirect responses should direct the
    user to insecure endpoints.
    """
    settings.DJOAUTH2_SSL_ONLY = False
    self.initialize(scope_names=['verify'])

    auth_code_generator = AuthorizationCodeGenerator(self.missing_redirect_uri)

    make_validation_endpoint(self.dummy_endpoint_uri, auth_code_generator)

    self.oauth_client.login(username=self.user.username, password='password')

    self.client.redirect_uri = 'http://locu.com/'
    self.client.save()

    response = self.oauth_client.make_authorization_request(
        client_id=self.client.key,
        scope_string=self.oauth_client.scope_string,
        endpoint=self.dummy_endpoint_uri)

    success_redirect = auth_code_generator.make_success_redirect()

    parsed_redirect_uri = urlparse(success_redirect.get('location'))
    redirect_location = urlunparse((
      parsed_redirect_uri.scheme,
      parsed_redirect_uri.netloc,
      parsed_redirect_uri.path,
      '',
      '',
      ''))

    self.assertEqual(redirect_location, self.client.redirect_uri)
    self.assertNotEqual(redirect_location, self.missing_redirect_uri)

