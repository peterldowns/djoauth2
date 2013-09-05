# coding: utf-8
from django.utils.functional import wraps

from djoauth2.access_token_authenticator import AccessTokenAuthenticator

def oauth_scope(*scope_names):
  """ Only allow requests with sufficient OAuth scope access."""
  scope_names = scope_names or ()
  if not scope_names:
    raise ValueError('Must supply at least one scope name to protect this endpoint.')
  
  def scope_decorator(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
      authenticator = AccessTokenAuthenticator(scope_names=scope_names)
      authenticator.validate(request)
      if authenticator.validation_exception:
        return authenticator.error_response()

      return view_func(authenticator, request, *args, **kwargs)

    return wrapper

  return scope_decorator


