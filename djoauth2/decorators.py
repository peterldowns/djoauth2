# coding: utf-8
from django.utils.functional import wraps

from djoauth2.access_token_authenticator import AccessTokenAuthenticator

def oauth_scope(*scope_names):
  """ Only allow requests with sufficient OAuth scope access.

  Returns a decorator that restricts requests to those that authenticate
  successfully and have access to the given scope names.

  For example, to restrict access to a given endpoint:

    >>> @oauth_scope('foo', 'bar')
    >>> def secret_attribute_endpoint(access_token, request, *args, **kwargs):
    >>>   # Because of the decorator, the function is guarnateed to only be run
    >>>   # if the request includes proper access to the 'foo' and 'bar'
    >>>   # scopes.
    >>>   user = access_token.user
    >>>   return HttpResponse(json.dumps({
    >>>       'super_secret_attribute' : user.super_secret_attribute
    >>>     })

  The first argument to the wrapped endpoint will now be an AccessToken
  object. The second argument will be the original HttpRequest, and all
  other parameters will follow.

  We strongly recommend that you use this decorator to protect your API
  endpoints instead of manually instantiating an AccessTokenAuthenticator
  object.
  """
  authenticator = AccessTokenAuthenticator(required_scope_names=scope_names)

  def scope_decorator(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
      access_token, error_response_arguments = authenticator.validate(request)

      if not access_token:
        return authenticator.make_error_response(*error_response_arguments)

      return view_func(access_token, request, *args, **kwargs)

    return wrapper

  return scope_decorator


