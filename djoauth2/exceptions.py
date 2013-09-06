# coding: utf-8
#TODO(peter): make these match with the actual error codes! 5.2, 4.1.x

class DJOAuthException(Exception):
  pass


class AuthenticationException(DJOAuthException):
  """Authentication exception base class."""
  pass


class InvalidRequest(AuthenticationException):
  error_name = 'invalid_request'


class InvalidToken(AuthenticationException):
  """The access token provided is expired, revoked, malformed, or
  invalid for other reasons."""
  error = 'invalid_token'


class InsufficientScope(AuthenticationException):
  """The request requires higher privileges than provided by the
  access token."""
  error = 'insufficient_scope'


class AccessTokenException(DJOAuthException):
  """Access Token exception base class."""
  pass


class InvalidRequest(AccessTokenException):
  """The request is missing a required parameter, includes an unsupported
  parameter or parameter value, repeats a parameter, includes multiple
  credentials, utilizes more than one mechanism for authenticating the client,
  or is otherwise malformed."""
  error = 'invalid_request'


class InvalidClient(AccessTokenException):
  """Client authentication failed (e.g. unknown client, no
  client credentials included, multiple client credentials
  included, or unsupported credentials type)."""
  error = 'invalid_client'


class UnauthorizedClient(AccessTokenException):
  """The client is not authorized to request an authorization
  code using this method."""
  error = 'unauthorized_client'


class InvalidGrant(AccessTokenException):
  """The provided authorization grant is invalid, expired,
  revoked, does not match the redirection URI used in the
  authorization request, or was issued to another client."""
  error = 'invalid_grant'


class UnsupportedGrantType(AccessTokenException):
  """The authorization grant type is not supported by the
  authorization server."""
  error = 'unsupported_grant_type'


class InvalidScope(AccessTokenException):
  """The requested scope is invalid, unknown, malformed, or
  exceeds the scope granted by the resource owner."""
  error = 'invalid_scope'


