# coding: utf-8
from django.http import HttpResponse

from djoauth2.conf import settings
from djoauth2.exceptions import AuthenticationException
from djoauth2.exceptions import InsufficientScope
from djoauth2.exceptions import InvalidRequest
from djoauth2.exceptions import InvalidToken
from djoauth2.models import AccessToken
from djoauth2.models import Scope
 
class AccessTokenAuthenticator(object):
  def __init__(self, required_scope_names=()):
    for name in required_scope_names:
      if not Scope.objects.filter(name=name).exists():
        raise ValueError('Scope with name "{}" does not exist.'.format(name))


  def validate(self, request):
    # TODO(peter): should this return an access token?
    try:
      if settings.DJOAUTH_SSL_ONLY and not request.is_secure():
        raise InvalidRequest('insecure request: must use TLS')

      http_authorization = request.meta.get('HTTP_AUTHORIZATION', '')
      if not http_authorization:
        raise InvalidRequest('missing HTTP_AUTHORIZATION header')

      try:
        auth_method, auth_value = http_authorization.strip().split(' ', 1)
      except ValueError:
        raise InvalidRequest('malformed HTTP_AUTHORIZATION header')

      if auth_method != 'Bearer':
        raise InvalidRequest('authentication method is not "Bearer"')
      
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
      return (None, validation_exception)


  def make_error_response(self,
                          validation_exception,
                          content='',
                          mimetype=None,
                          content_type=settings.DEFAULT_CONTENT_TYPE):
      
    response = HttpResponse(content=content,
                            mimetype=mimetype,
                            content_type=content_type)
    
    error_name = getattr(validation_exception,
                         'error_name',
                         'invalid_request')
    error_description = getattr(validation_exception,
                                'message',
                                'Invalid Request.')

    # The format of this response is not set by the specification; read
    # http://tools.ietf.org/html/rfc6749#section-7.2 for more details.
    # For consistency's sake, this implementation adopts the standard
    # format described by http://tools.ietf.org/html/rfc6749#section-4.1
    # and http://tools.ietf.org/html/rfc6749#section-6 .
    #
    # NOT TRUE! Actually, we respond using the specification from 
    # http://tools.ietf.org/html/rfc6750#section-3.1
    authenticate_header = [
        'Bearer realm="{}"'.format(settings.DJOAUTH_REALM),
        'error="{}"'.format(error_name),
        'error_description="{}"'.format(error_description),
      ]
    # TODO(peter): if the Client made a request without Bearer
    # authentication, then only respond with 401 Bearer and no 'error' or
    # 'error_description' or 'scope' fields.

    if isinstance(self.validation_exception, InsufficientScope):
      authenticate_header.append('scope="{}"'.format(' '.join(self.required_scope_names)))
      response.status_code = 403
    elif isinstance(self.validation_exception, InvalidRequest):
      response.status_code = 400
    else:
      response.status_code = 401

    response['WWW-Authenticate'] = ', '.join(authenticate_header)
    return response


