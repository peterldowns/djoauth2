# coding: utf-8

class DJOAuthException(Exception):
  pass

class AuthenticationException(DJOAuthException):
  """Authentication exception base class."""
  pass


class InvalidRequest(AuthenticationException):
  """The request is missing a required parameter, includes an
  unsupported parameter or parameter value, repeats the same
  parameter, uses more than one method for including an access
  token, or is otherwise malformed."""
  error_name = 'invalid_request'


class InvalidToken(AuthenticationException):
  """The access token provided is expired, revoked, malformed, or
  invalid for other reasons."""
  error = 'invalid_token'


class InsufficientScope(AuthenticationException):
  """The request requires higher privileges than provided by the
  access token."""
  error = 'insufficient_scope'

