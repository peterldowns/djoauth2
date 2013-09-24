# coding: utf-8
from urllib import urlencode
from urlparse import urlparse

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.http.request import absolute_http_url_re
from django.shortcuts import render
from django.forms import Form
from django.views.decorators.http import require_http_methods

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

    >>> def authorization(request):
    >>>   auth_code_generator = AuthorizationCodeGenerator(
    >>>       '/oauth2/missing_redirect_uri/')
    >>>   try:
    >>>     auth_code_generator.validate(request)
    >>>   except AuthorizationException as e:
    >>>     return auth_code_generator.make_error_redirect()
    >>>
    >>>   if request.method == 'GET':
    >>>     # Show a page for the user to see the scope request. Include a form
    >>>     # for the user to authorize or reject the request. Make sure to
    >>>     # include all of the # original authorization request's parameters
    >>>     # with the form so that they # can be accessed when the user submits
    >>>     # the form.
    >>>     original_request_parameters = (
    >>>         auth_code_generator.get_request_uri_parameters())
    >>>     # See the template example below.
    >>>     template_render_context = {
    >>>         'form': Form(),
    >>>         'client': auth_code_generator.client,
    >>>         'scopes': auth_code_generator.valid_scope_objects,
    >>>         # Assumes that this endpoint is connected to
    >>>         # the '/oauth/authorization/' URL.
    >>>         'form_action': ('/oauth2/authorization/?' +
    >>>                         original_request_parameters),
    >>>       }
    >>>     return render(request,
    >>>                   'oauth2server/authorization_page.html',
    >>>                   template_render_context)
    >>>   elif request.method == 'POST':
    >>>     # Check the form the user submits (see the template below.)
    >>>     if request.POST.get('user_action') == 'Accept':
    >>>       return auth_code_generator.make_success_redirect()
    >>>     else:
    >>>       return auth_code_generator.make_error_redirect()

  An example template (``'oauth2server/authorization_page.html'`` from the
  above example) should look something like this:

  .. code-block:: html

      <p>{{client.name}} is requesting access to the following scopes:</p>

      <ul>
        {% for scope in scopes %}
        <li> <b>{{scope.name}}</b>: {{scope.description}} </li>
        {% endfor %}
      </ul>


      <form action="{{form_action}}" method="POST">
        {% csrf_token %}
        <div style="display: none;"> {{form}} </div>
        <input type="submit" name="user_action" value="Decline"/>
        <input type="submit" name="user_action" value="Accept"/>
      </form>

  We **strongly recommend** that you avoid instantiating this class. Instead,
  prefer the :py:func:`djoauth2.authorization.make_authorization_endpoint`
  """
  def __init__(self, missing_redirect_uri):
    """ Create a new AuthorizationCodeGenerator.

    :param missing_redirect_uri: a string URI to which to redirect the user if
        the authorization request is not valid and no redirect is able to be
        parsed from the request.
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
    """ Check that a Client's authorization request is valid.

    If the request is invalid or malformed in any way, raises the appropriate
    exception.  Read `the relevant section of the specification
    <http://tools.ietf.org/html/rfc6749#section-4.1 .>`_ for descriptions of
    each type of error.

    :raises: a :py:class:`AuthorizationException` if the request is invalid.
    """

    # From http://tools.ietf.org/html/rfc6749#section-3.1 :
    #
    #     The authorization server MUST support the use of the HTTP "GET"
    #     method [RFC2616] for the authorization endpoint and MAY support the
    #     use of the "POST" method as well.
    #
    if not request.method in ['GET', 'POST']:
      raise InvalidRequest('must be GET or POST request')

    if settings.DJOAUTH2_SSL_ONLY and not request.is_secure():
      raise InvalidRequest('all requests must use TLS')

    self.request = request
    self.user = request.user
    if not self.user.is_authenticated():
      raise UnauthenticatedUser('user must be authenticated')

    client_id = request.REQUEST.get('client_id')
    if not client_id:
      raise InvalidRequest('no "client_id" provided')

    try:
      self.client = Client.objects.get(key=client_id)
    except Client.DoesNotExist:
      raise InvalidRequest('"client_id" does not exist')

    # From http://tools.ietf.org/html/rfc6749#section-3.1.2.3 :
    #
    #     If multiple redirection URIs have been registered, if only part of
    #     the redirection URI has been registered, or if no redirection URI has
    #     been registered, the client MUST include a redirection URI with the
    #     authorization request using the "redirect_uri" request parameter.
    #
    self.request_redirect_uri = request.REQUEST.get('redirect_uri')
    if not (self.client.redirect_uri or self.request_redirect_uri):
      raise InvalidRequest('no "redirect_uri" provided or registered')

    # From http://tools.ietf.org/html/rfc6749#section-3.1.2.3 :
    #
    #     When a redirection URI is included in an authorization request, the
    #     authorization server MUST compare and match the value received
    #     against at least one of the registered redirection URIs (or URI
    #     components) as defined in [RFC3986] Section 6, if any redirection
    #     URIs were registered.  If the client registration included the full
    #     redirection URI, the authorization server MUST compare the two URIs
    #     using simple string comparison as defined in [RFC3986] Section 6.2.1.
    #
    if (self.client.redirect_uri and
          self.request_redirect_uri and
          self.client.redirect_uri != self.request_redirect_uri):
      raise InvalidRequest('"redirect_uri" does not matched the registered URI')

    # From http://tools.ietf.org/html/rfc6749#section-3.1.2 :
    #
    #     The redirection endpoint URI MUST be an absolute URI as defined by
    #     [RFC3986] Section 4.3.
    #
    redirect_uri = self.client.redirect_uri or self.request_redirect_uri
    if not absolute_http_url_re.match(redirect_uri):
      raise InvalidRequest('"redirect_uri" must be absolute')

    # From http://tools.ietf.org/html/rfc6749#section-3.1.2 :
    #
    #     The endpoint URI MUST NOT include a fragment component.
    #
    if urlparse(redirect_uri).fragment:
      raise InvalidRequest('"redirect_uri" must not contain a fragment')

    # From http://tools.ietf.org/html/rfc6749#section-3.1.2.1 :
    #
    #     The redirection endpoint SHOULD require the use of TLS as described
    #     in Section 1.6 when the requested response type is "code" or "token",
    #     or when the redirection request will result in the transmission of
    #     sensitive credentials over an open network.  This specification does
    #     not mandate the use of TLS because at the time of this writing,
    #     requiring clients to deploy TLS is a significant hurdle for many
    #     client developers.  If TLS is not available, the authorization server
    #     SHOULD warn the resource owner about the insecure endpoint prior to
    #     redirection (e.g., display a message during the authorization
    #     request).
    #
    if (settings.DJOAUTH2_SSL_ONLY and
        urlparse(redirect_uri).scheme != 'https'):
      raise InvalidRequest('"redirect_uri" must use TLS')

    # Only store the redirect_uri value if it validates successfully. The
    # 'make_error_redirect' method will use the 'missing_redirect_uri' passed
    # to the '__init__' method if 'self.redirect_uri' is None.
    self.redirect_uri = redirect_uri

    # From http://tools.ietf.org/html/rfc6749#section-3.1.1 :
    #
    #     The client informs the authorization server of the desired grant type
    #     using the following parameter:
    #
    #     response_type
    #           REQUIRED.  The value MUST be one of "code" for requesting an
    #           authorization code as described by Section 4.1.1, "token" for
    #           requesting an access token (implicit grant) as described by
    #           Section 4.2.1, or a registered extension value as described by
    #           Section 8.4.
    #
    # This implementation only supports the "code" "response_type".
    response_type = request.REQUEST.get('response_type')
    if response_type != 'code':
      raise UnsupportedResponseType('"response_type" must be "code"')

    # As recommended by http://tools.ietf.org/html/rfc6749#section-4.1.1 :
    #
    #     state
    #           RECOMMENDED.  An opaque value used by the client to maintain
    #           state between the request and callback.  The authorization
    #           server includes this value when redirecting the user-agent back
    #           to the client.  The parameter SHOULD be used for preventing
    #           cross-site request forgery as described in Section 10.12.
    #
    # and necessary for the CSRF recommendation mandated by
    # http://tools.ietf.org/html/rfc6749#section-10.12 :
    #
    #     The client MUST implement CSRF protection for its redirection URI.
    #     This is typically accomplished by requiring any request sent to the
    #     redirection URI endpoint to include a value that binds the request to
    #     the user-agent's authenticated state (e.g., a hash of the session
    #     cookie used to authenticate the user-agent).  The client SHOULD
    #     utilize the "state" request parameter to deliver this value to the
    #     authorization server when making an authorization request.
    #
    self.state = request.REQUEST.get('state')
    if settings.DJOAUTH2_REQUIRE_STATE and not self.state:
      raise InvalidRequest('"state" must be included')

    requested_scope_string = request.REQUEST.get('scope', '')
    if not requested_scope_string:
      raise InvalidRequest('no "scope" provided')

    requested_scope_names = set(requested_scope_string.split(' '))
    self.valid_scope_objects = Scope.objects.filter(
        name__in=requested_scope_names)
    valid_scope_names = {scope.name for scope in self.valid_scope_objects}
    if valid_scope_names < requested_scope_names:
      raise InvalidScope('The following scopes are invalid: {}'.format(
          ', '.join('"{}"'.format(name)
                    for name in (requested_scope_names - valid_scope_names))))



  def get_request_uri_parameters(self, as_dict=False):
    """ Return the URI parameters from a request passed to the 'validate' method

    The query parameters returned by this method **MUST** be included in the
    ``action=""`` URI of the authorization form presented to the user. This
    carries the original authorization request parameters across the request to
    show the form to the request that submits the form.

    :param as_dict: default ``False``. If ``True``, returns the parameters as a
        dictionary. If ``False``, returns the parameters as a URI-encoded
        string.
    """
    if not self.request:
      raise ValueError('request must have been passed to the "validate" method')

    return (dict if as_dict else urlencode)(self.request.REQUEST.items())

  def make_error_redirect(self):
    """ Return a Django ``HttpResponseRedirect`` describing the request failure.

    If the :py:meth:`validate` method raises an error, the authorization
    endpoint should return the result of calling this method like so:

      >>> auth_code_generator = (
      >>>     AuthorizationCodeGenerator('/oauth2/missing_redirect_uri/'))
      >>> try:
      >>>   auth_code_generator.validate(request)
      >>> except AuthorizationException:
      >>>   return auth_code_generator.make_error_redirect()

    If there is no known Client ``redirect_uri`` (because it is malformed, or
    the Client is invalid, or if the supplied ``redirect_uri`` does not match
    the regsitered value, or some other request failure) then the response will
    redirect to the ``missing_redirect_uri`` passed to the :py:meth:`__init__`
    method.
    """
    if not self.redirect_uri:
      return HttpResponseRedirect(self.missing_redirect_uri)

    validation_error = AccessDenied('user denied the request')
    response_params = get_error_details(validation_error)
    # From http://tools.ietf.org/html/rfc6749#section-4.1.2.1 :
    #
    #     REQUIRED if the "state" parameter was present in the client
    #     authorization request.  The exact value received from the
    #     client.
    #
    if self.state is not None:
      response_params['state'] = self.state
    return HttpResponseRedirect(
        update_parameters(self.redirect_uri, response_params))

  def make_success_redirect(self):
    """ Return a Django ``HttpResponseRedirect`` describing the request success.

    The custom authorization endpoint should return the result of this method
    when the user grants the Client's authorization request. The request is
    assumed to have successfully been vetted by the :py:meth:`validate` method.
    """
    new_authorization_code = AuthorizationCode.objects.create(
        user=self.user,
        client=self.client,
        redirect_uri=(self.redirect_uri if self.request_redirect_uri else None)
    )
    new_authorization_code.scopes = self.valid_scope_objects
    new_authorization_code.save()

    response_params = {'code': new_authorization_code.value}
    # From http://tools.ietf.org/html/rfc6749#section-4.1.2 :
    #
    #     REQUIRED if the "state" parameter was present in the client
    #     authorization request.  The exact value received from the
    #     client.
    #
    if self.state is not None:
      response_params['state'] = self.state
    return HttpResponseRedirect(
        update_parameters(self.redirect_uri, response_params))



# TODO(peter): add a callback for successful authorization and unsuccessful
# authorization -- or just use signals instead? Yeah, use signals.
def make_authorization_endpoint(missing_redirect_uri,
                                authorization_endpoint_uri,
                                authorization_template_name):
  """ Returns a endpoint that handles OAuth authorization requests.


  The template described by ``authorization_template_name`` is rendered with a
  Django ``RequestContext`` with the following variables:

  * ``form``: a Django ``Form`` with no fields.
  * ``client``: The :py:class:`djoauth2.models.Client` requesting access to the
    user's scopes.
  * ``scopes``: A list of :py:class:`djoauth2.models.Scope`, one for each of
    the scopes requested by the client.
  * ``form_action``: The URI to which the form should be submitted -- use this
    value in the ``action=""`` attribute on a ``<form>`` element.

  :param missing_redirect_uri: a string, the URI to which to redirect the user
      when the request is made by a client without a valid redirect URI.

  :param authorization_endpoint_uri: a string, the URI of this endpoint. Used
      by the authorization form so that the form is submitted to this same
      endpoint.

  :param authorization_template_name: a string, the name of the template to
      render when handling authorization requests.

  :rtype: A view function endpoint.
  """
  @login_required
  @require_http_methods(['GET', 'POST'])
  def authorization_endpoint(request):
    auth_code_generator = AuthorizationCodeGenerator(missing_redirect_uri)

    try:
      auth_code_generator.validate(request)
    except AuthorizationException as e:
      return auth_code_generator.make_error_redirect()

    if request.method == 'GET':
      return render(request, authorization_template_name, {
          'form': Form(),
          'client': auth_code_generator.client,
          'scopes': auth_code_generator.valid_scope_objects,
          'form_action': update_parameters(
              authorization_endpoint_uri,
              auth_code_generator.get_request_uri_parameters(as_dict=True)),
        })

    if request.method == 'POST':
      form = Form(request)
      if form.is_valid() and request.POST.get('user_action') == 'Accept':
        return auth_code_generator.make_success_redirect()
      else:
        return auth_code_generator.make_error_redirect()

  return authorization_endpoint


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

