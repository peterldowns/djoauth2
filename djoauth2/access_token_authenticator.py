# coding: utf-8
import json

from django.http import HttpResponse

from djoauth2.conf import settings
from djoauth2.exceptions import DJOAuthException
from djoauth2.exceptions import get_error_details
from djoauth2.models import AccessToken
from djoauth2.models import Scope

class AccessTokenAuthenticator(object):
  """ Allows easy authentication checking and error response creation.

  See the 'validate' method's docstring for a usage example. We strongly
  recommend that you use the 'djoauth2.decorators.oauth_scope' method to
  protect your API endpoints instead of manually instatiating this object.
  """

  def __init__(self, required_scope_names=()):
    """ Store the names of the scopes that will be checked. """
    self.required_scope_names = required_scope_names
    for name in required_scope_names:
      if not Scope.objects.filter(name=name).exists():
        raise ValueError('Scope with name "{}" does not exist.'.format(name))


  def validate(self, request):
    """ Checks a request for proper authentication details.

    Returns a tuple of (access_token, error_response_arguments), which
    are described below.

    @access_token: an AccessToken if the request is successfully authenticated,
        otherwise None.
    @error_response_arguments: None if the request is successfully
        authenticated, otherwise a tuple of arguments to be used in a call to
        the 'make_error_response' method.

    For example, to restrict access to a given endpoint:

        >>> def foo_bar_resource(request, *args, **kwargs):
        >>>   authenticator = AccessTokenAuthenticator(
        >>>       required_scope_names=('foo', 'bar'))
        >>>
        >>>   access_token, error_args = authenticator.validate(request)
        >>>   if not access_token:
        >>>     return authenticator.make_error_response(*error_args)
        >>>
        >>>   # ... can now return use access_token
        >>>

    """

    # From http://tools.ietf.org/html/rfc6750#section-3.1 :
    #
    #        If the request lacks any authentication information (e.g., the
    #        client was unaware that authentication is necessary or attempted
    #        using an unsupported authentication method), the resource server
    #        SHOULD NOT include an error code or other error information.
    #
    # In the case that the request fails to validate, this flag will
    # be returned and should be passed to the 'make_error_response' method
    # in order to comply with the specification and restrict error information.
    expose_errors = False

    try:
      if settings.DJOAUTH2_SSL_ONLY and not request.is_secure():
        raise InvalidRequest('insecure request: must use TLS')

      http_authorization = request.META.get('HTTP_AUTHORIZATION', '')
      if not http_authorization:
        raise InvalidRequest('missing HTTP_AUTHORIZATION header')

      try:
        auth_method, auth_value = http_authorization.strip().split(' ', 1)
      except ValueError:
        raise InvalidRequest('malformed HTTP_AUTHORIZATION header')

      if auth_method != 'Bearer':
        raise InvalidRequest('authentication method is not "Bearer"')

      # Used in the case that the request does not validate. See comment above.
      # At this point in the validation, it is certain that the Client
      # attempted to authenticate via the 'bearer' method.
      expose_errors = True

      try:
        access_token = AccessToken.objects.get(value=auth_value)
      except AccessToken.DoesNotExist:
        raise InvalidToken('access token does not exist')

      if access_token.is_expired():
        raise InvalidToken('access token is expired')

      if not access_token.has_scope(*self.required_scope_names):
        raise InsufficientScope('access token has insufficient scope')

      return (access_token, None)

    except AuthenticationException as validation_exception:
      return (None, (validation_exception, expose_errors))


  def make_error_response(self, validation_exception, expose_errors):
    """ Return an appropriate response on authentication failure.

    Read the specification: http://tools.ietf.org/html/rfc6750#section-3.1 .

    In case of an error, the specification only details the inclusion of the
    'WWW-Authenticate' header. Additionally, when allowed by the specification,
    we respond with error details formatted in JSON in the body of the
    response.
    """
    authenticate_header = ['Bearer realm="{}"'.format(settings.DJOAUTH2_REALM)]

    if not expose_errors:
      response = HttpResponse(status=400)
      response['WWW-Authenticate'] = ', '.join(authenticate_header)
      return response

    status_code = 401
    error_details = get_error_details(validation_exception)

    if isinstance(validation_exception, InvalidRequest):
      status_code = 400
    elif isinstance(validation_exception, InvalidToken):
      status_code = 401
    elif isinstance(validation_exception, InsufficientScope):
      error_details['scope'] = ' '.join(self.required_scope_names)
      status_code = 403

    # TODO(peter): should we return response details as JSON? This is not
    # touched upon by the spec and may limit use of this library.  Many
    # programmers use other transport languaes such as YAML or XML. All of the
    # error information is already included in the headers.
    response = HttpResponse(content=json.dumps(error_details),
                            content_type='application/json',
                            status=status_code)

    for key, value in error_details.iteritems():
      authenticate_header.append('{}="{}"'.format(key, value))

    response['WWW-Authenticate'] = ', '.join(authenticate_header)
    return response


class AuthenticationException(DJOAuthException):
  """ Base class for exceptions related to API request authentication.

  Read the Bearer Token specification for more details:
    * http://tools.ietf.org/html/rfc6750#section-3.1
    * http://tools.ietf.org/html/rfc6750#section-6.2
  """
  pass


class InvalidRequest(AuthenticationException):
  """ The request is missing a required parameter, includes an unsupported
  parameter or parameter value, repeats the same parameter, uses more than one
  method for including an access token, or is otherwise malformed. The
  resource server SHOULD respond with the HTTP 400 (Bad Request) status code.
  """
  error_name = 'invalid_request'


class InvalidToken(AuthenticationException):
  """ The access token provided is expired, revoked, malformed, or invalid for
  other reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized)
  status code. The client MAY request a new access token and retry the
  protected resource request.
  """
  error_name = 'invalid_token'


class InsufficientScope(AuthenticationException):
  """ The request requires higher privileges than provided by the access token.
  The resource server SHOULD respond with the HTTP 403 (Forbidden) status code
  and MAY include the "scope" attribute with the scope necessary to access the
  protected resource.
  """
  error_name = 'insufficient_scope'

