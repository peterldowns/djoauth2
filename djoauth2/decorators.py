# coding: utf-8
from django.utils.functional import wraps

from djoauth2.access_token_authenticator import AccessTokenAuthenticator

def oauth_scope(*scope_names):
  """ Only allow requests with sufficient OAuth scope access."""
  authenticator = AccessTokenAuthenticator(required_scopes=scope_names)

  def scope_decorator(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
      access_token, auth_exception = authenticator.validate(request)
      if auth_exception:
        return authenticator.make_error_response(auth_exception)
      
      return view_func(access_token, request, *args, **kwargs)

    return wrapper

  return scope_decorator


