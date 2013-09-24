# coding: utf-8


class DJOAuthException(Exception):
  """ Base exception class for all OAuth-related exceptions. """
  error_name = 'invalid_request'
  status_code = 400


def get_error_details(exception):
  """ Return details about an OAuth exception.

  Returns a mapping with two keys, ``'error'`` and ``'error_description'``,
  that are used in all error responses described by the OAuth 2.0
  specification. Read more at:

  * http://tools.ietf.org/html/rfc6749
  * http://tools.ietf.org/html/rfc6750
  """
  return {
    'error': getattr(exception, 'error_name', 'invalid_request'),
    'error_description': str(exception) or '(no description available)'
  }


