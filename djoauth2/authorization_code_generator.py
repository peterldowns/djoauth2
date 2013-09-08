# coding: utf-8
from urllib import urlencode

from django.http.request import absolute_http_url_re
from django.http import HttpResponseRedirect

from djoauth2.conf import settings
from djoauth2.exceptions import DJOAuthException
from djoauth2.exceptions import get_error_details
from djoauth2.helpers import update_parameters
from djoauth2.models import AuthorizationCode
from djoauth2.models import Client
from djoauth2.models import Scope


class AuthorizationCodeGenerator(object):
  """ Allows easy authorization request validation, code generation, and
  redirection creation.

  Use as part of your authorization page endpoint like so:

      >>> def authorization(request, *args, **kwargs):
      >>>   auth_code_generator = AuthorizationCodeGenerator('/oauth/missing_redirect_uri')
      >>>   try:
      >>>     auth_code_generator.validate(request)
      >>>   except AuthorizationException:
      >>>     return auth_code_generator.error_redirect()
      >>>
      >>>   if request.method == 'GET':
      >>>     # Show a page for the user to see the scope request. Include a
      >>>     # form for the user to authorize or reject the request.
      >>>     # Make sure to include all of the original authorization request's
      >>>     # parameters with the form so that they can be accessed when the user
      >>>     # submits the form
      >>>     original_request_parameters = auth_code_generator.get_request_uri_parameters()
      >>>     # See the template example below.
      >>>     template_render_context = {
      >>>         'form' : Form(),
      >>>         # Assumes that this endpoint is connected to '/oauth/authorize/'
      >>>         'form_action': '/oauth/authorize/?' + original_request_parameters,
      >>>       }
      >>>     return render('oauth/authorize_page.html', template_render_context)
      >>>   elif request.method == 'POST':
      >>>     # Check the form the user submits. See the template example below.
      >>>     if request.POST.get('user_action') == 'Accept':
      >>>       return auth_code_generator.make_success_redirect()
      >>>     else:
      >>>       return auth_code_generator.make_error_redirect()
      >>>

  An example of the 'oauth/authorize_page.html' template:

      <form action="{{form_action}}" method="POST">
        {{csrf_token}}
        <div style="display: none;"> {{form}} </div>
        <input type="submit" name="user_action" value="Decline"/>
        <input type="submit" name="user_action" value="Accept"/>
      </form>

  """
  def __init__(self, missing_redirect_uri):
    """ Create a new AuthorizationCodeGenerator.

    @missing_redirect_uri: a string URI to which to redirect the user if the
        authorization request is not valid and no redirect is able to be parsed
        from the request.
    """
    self.missing_redirect_uri = missing_redirect_uri
    # Values that will be set by the 'validate' method.
    self.user = None
    self.client = None
    self.redirect_uri = None
    self.request_redirect_uri = None
    self.valid_scope_objects = None
    self.state = None
    self.request = None

  def validate(self, request):
    """ Raise an exception if the authorization request is invalid.

    Read the specification: http://tools.ietf.org/html/rfc6749#section-4.1 .
    """
    if settings.DJOAUTH2_SSL_ONLY and not request.is_secure():
      raise InvalidRequest('all requests must use TLS')

    self.request = request
    self.user = request.user
    if not self.user.is_authenticated():
      raise UnauthenticatedUser('user must be authenticated')

    response_type = request.REQUEST.get('response_type')
    if response_type != 'code':
      raise UnsupportedResponseType('"response_type" must be "code"')

    self.state = request.REQUEST.get('state')
    if settings.DJOAUTH2_REQUIRE_STATE and not self.state:
      raise InvalidRequest('"state" must be included')

    scope_names = set(request.REQUEST.get('scope', '').split(' '))
    self.valid_scope_objects = Scope.objects.filter(name__in=scope_names)
    valid_scope_names = {scope.name for scope in self.valid_scope_objects}
    if valid_scope_names < scope_names:
      raise InvalidScope('the following scopes do not exist: {}'.format(
          ', '.join('"{}"'.format(name)
                    for name in (scope_names - valid_scope_names))
        ))

    client_id = request.REQUEST.get('client_id')
    if not client_id:
      raise InvalidRequest('no "client_id" provided')

    try:
      self.client = Client.objects.get(key=client_id)
    except Client.DoesNotExist:
      raise InvalidRequest('"client_id" does not exist')

    self.request_redirect_uri = request.REQUEST.get('redirect_uri')
    if not (self.client.redirect_uri or self.request_redirect_uri):
      raise InvalidRequest('no "redirect_uri" provided or registered')

    if (self.client.redirect_uri and
          self.request_redirect_uri and
          self.client.redirect_uri != self.request_redirect_uri):
      raise InvalidRequest('"redirect_uri" does not matched the registered URI')

    redirect_uri = self.client.redirect_uri or self.request_redirect_uri
    # TODO(peter): add this requirement as an on_save validation on the Client
    # object.
    if not absolute_http_url_re.match(redirect_uri):
      raise InvalidRequest('"redirect_uri" must be absolute')

    # Only store the redirect_uri value if it validates successfully. The
    # 'make_error_redirect' method will use the 'missing_redirect_uri' passed
    # to the '__init__' method if 'self.redirect_uri' is None.
    self.redirect_uri = redirect_uri

  def get_request_uri_parameters(self, as_dict=False):
    """ Return the URI parameters from a request passed to the 'validate' method.

    @as_dict: if True, returns the parameters as a dictionary. If False, returns
        the parameters as a URI-encoded string.

    The parameters returned by this method MUST be included in the 'action' URL
    of the authorization form presented to the user. This carries the original
    authorization request parameters across the request.
    """
    if not self.request:
      raise ValueError('request must have been passed to the "validate" method')

    if as_dict:
      return self.request.REQUEST.dict()

    return urlencode(self.request.REQUEST.items())


  def make_error_redirect(self):
    """ Return an HttpResponseRedirect when the authorization request fails.

    If the 'validate' method raises an error, the authorization endpoint should
    return the result of this method like so:

      >>> auth_code_generator = AuthorizationCodeGenerator('/oauth2/missing_redirect_uri/')
      >>> try:
      >>>   auth_code_generator.validate(request)
      >>> except AuthorizationException:
      >>>   return auth_code_generator.make_error_redirect()

    If there is no known "redirect_uri" (because it is malformed, or the Client
    is invalid, or if the supplied "redirect_uri" does not match the regsitered
    value, or some other request failure) then the response will redirect to
    the 'missing_redirect_uri' passed to the '__init__' method.
    """
    if not self.redirect_uri:
      return HttpResponseRedirect(self.missing_redirect_uri)

    validation_error = AccessDenied('user denied the request')
    response_params = get_error_details(validation_error)
    if settings.DJOAUTH2_REQUIRE_STATE:
      response_params['state'] = self.state
    return HttpResponseRedirect(
        update_parameters(self.redirect_uri, response_params))


  def make_success_redirect(self):
    """ Return an HttpResponseRedirect when the authorization request succeeds.

    The custom authorization endpoint should return the result of this method
    when the user grants the Client's authorization request. The request is
    assumed to have successfully been vetted by the 'validate' method.
    """
    new_authorization_code = AuthorizationCode.objects.create(
        user=self.user,
        client=self.client,
        redirect_uri=self.request_redirect_uri if self.request_redirect_uri else None
    )
    new_authorization_code.scopes = self.valid_scope_objects
    new_authorization_code.save()

    response_params = {'code': new_authorization_code.value}
    if settings.DJOAUTH2_REQUIRE_STATE:
      response_params['state'] = self.state
    return HttpResponseRedirect(
        update_parameters(self.redirect_uri, response_params))


class AuthorizationException(DJOAuthException):
  """ Base class for authorization-related exceptions.

  Read the specification: http://tools.ietf.org/html/rfc6749#section-4.1.2.1 .
  """


class UnauthenticatedUser(AuthorizationException):
  """ Raised when the user is not authenticated during authorization.

  Not part of the OAuth specification.
  """


class InvalidRequest(AuthorizationException):
  """ The request is missing a required parameter, includes an invalid
  parameter value, includes a parameter more than once, or is otherwise
  malformed.
  """
  error_name = 'invalid_request'


class UnauthorizedClient(AuthorizationException):
  """ The client is not authorized to request an authorization code using this
  method.
  """
  error_name = 'unauthorized_client'


class AccessDenied(AuthorizationException):
  """ The resource owner or authorization server denied the request. """
  error_name = 'access_denied'


class UnsupportedResponseType(AuthorizationException):
  """ The authorization server does not support obtaining an authorization code
  using this method.
  """
  error_name = 'unsupported_response_type'


class InvalidScope(AuthorizationException):
  """ The requested scope is invalid, unknown, or malformed. """
  error_name = 'invalid_scope'


class ServerError(AuthorizationException):
  """  The authorization server encountered an unexpected condition that
  prevented it from fulfilling the request. (This error code is needed because
  a 500 Internal Server Error HTTP status code cannot be returned to the client
  via an HTTP redirect.)
  """
  error_name = 'server_error'


class TemporarilyUnavailable(AuthorizationException):
  """ The authorization server is currently unable to handle the request due to
  a temporary overloading or maintenance of the server. (This error code is
  needed because a 503 Service Unavailable HTTP status code cannot be returned
  to the client via an HTTP redirect.) """
  error_name = 'temporarily_unavailable'

