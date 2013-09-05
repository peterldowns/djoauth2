# coding: utf-8
from django.http import HttpResponse

from djoauth2.models import AccessToken, Scope
from djoauth2.conf import settings
from djoauth2.exceptions import (AuthenticationException,
                                 InsufficientScope,
                                 InvalidRequest,
                                 InvalidToken)
 
class AccessTokenAuthenticator(object):
  def __init__(self, scope_names=None):
    self.attempted_validation = False
    self.validation_exception = None
    
    self.scope_names = scope_names or []
    self.scope_objects = [
        Scope.objects.get(name=scope_name)
        for scope_name in self.scope_names]
    
    def validate(self, request):
      try:
        self.attempted_validation = True
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

        if not access_token.has_scope(*self.scope_names):
          raise InsufficientScope('access token has insufficient scope')

      except AuthenticationException as validation_exception:
        self.validation_exception = validation_exception


    def error_response(self,
                       content='',
                       mimetype=None,
                       content_type=settings.DEFAULT_CONTENT_TYPE):
      response = HttpResponse(content=content,
                               mimetype=mimetype,
                               content_type=content_type)
      
      if not self.attempted_validation:
        response['WWW-Authenticate'] = (
            'Bearer realm="{}"'.format(settings.DJOAUTH_REALM))
        response.status_code = 401
        return response

      error_name = getattr(self.validation_exception,
                           'error_name',
                           'invalid_request')
      error_description = getattr(self.validation_exception,
                                  'message',
                                  'Invalid Request.')

      authenticate_header = [
          'Bearer realm="{}"'.format(settings.DJOAUTH_REALM),
          # TODO(peter): is this set by a spec?
          'error="{}"'.format(error_name),
          'error_description="{}"'.format(error_description),
          ]

      if isinstance(self.validation_exception, InsufficientScope):
        authenticate_header.append('scope="{}"'.format(' '.join(self.scope_names)))
        response.status_code = 403
      elif isinstance(self.validation_exception, InvalidToken):
        response.status_code = 401
      elif isinstance(self.validation_exception, InvalidRequest):
        response.status_code = 400
      else:
        response.status_code = 401

      response['WWW-Authenticate'] = ', '.join(authenticate_header)
      return response


