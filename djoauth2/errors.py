# coding: utf-8


class DJOAuthError(Exception):
  """ Base class for all OAuth-related errors. """
  error_name = 'invalid_request'
  status_code = 400


def get_error_details(error):
  """ Return details about an OAuth error.

  Returns a mapping with two keys, ``'error'`` and ``'error_description'``,
  that are used in all error responses described by the OAuth 2.0
  specification. Read more at:

  * http://tools.ietf.org/html/rfc6749
  * http://tools.ietf.org/html/rfc6750
  """
  return {
    'error': getattr(error, 'error_name', 'invalid_request'),
    'error_description': str(error) or '(no description available)'
  }


