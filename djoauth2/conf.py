# coding: utf-8
from django.conf import settings

from appconf import AppConf

class DJOAuth2Conf(AppConf):
  """ Default OAuth-related settings.

  We recommend that you DO NOT override these settings. Doing so can
  break compliance with the OAuth specification, and/or introduce large
  security flaws into the authentication process. Please read
  through the 'Security Considerations' (
  http://tools.ietf.org/html/rfc6749#section-10 ) and convince yourself that
  you really know what you're doing before changing any of these values.
  """
  class Meta:
    prefix = 'djoauth2'

  ACCESS_TOKEN_LENGTH = 30
  ACCESS_TOKEN_LIFETIME = 3600
  ACCESS_TOKENS_REFRESHABLE = True

  AUTHORIZATION_CODE_LENGTH = 30
  # The specification ( http://tools.ietf.org/html/rfc6749#section-4.1.1 )
  # recommends a liftime of 10 minutes.
  AUTHORIZATION_CODE_LIFETIME = 600

  CLIENT_KEY_LENGTH = 30
  CLIENT_SECRET_LENGTH = 30

  REFRESH_TOKEN_LENGTH = 30

  # The specification does not specify any particular realm, and I am unable
  # to get a good idea of how the value might be used from anywhere else on
  # the internet. If you have a good understanding of HTTP Authorization Realms,
  # please explain them to me!
  REALM = ''

  # The "state" parameter is used during requests for AuthorizationCode
  # objects, because those requests redirect the user's browser back to the
  # Client's registered endpoint. From the specification (
  # http://tools.ietf.org/html/rfc6749#section-10.12 ):
  #
  #     The client MUST implement CSRF protection for its redirection URI.
  #     This is typically accomplished by requiring any request sent to the
  #     redirection URI endpoint to include a value that binds the request to
  #     the user-agent's authenticated state (e.g., a hash of the session
  #     cookie used to authenticate the user-agent).  The client SHOULD utilize
  #     the "state" request parameter to deliver this value to the
  #     authorization server when making an authorization request.
  #
  # If you would like to ignore the specification's recommendations and
  # introduce a security hole, change this value to False.
  REQUIRE_STATE = True

  # From http://tools.ietf.org/html/rfc6749#section-3.1.2.1 :
  #
  #     The redirection endpoint SHOULD require the use of TLS as described in
  #     Section 1.6 when the requested response type is "code" or "token", or
  #     when the redirection request will result in the transmission of
  #     sensitive credentials over an open network.  This specification does
  #     not mandate the use of TLS because at the time of this writing,
  #     requiring clients to deploy TLS is a significant hurdle for many client
  #     developers.  If TLS is not available, the authorization server SHOULD
  #     warn the resource owner about the insecure endpoint prior to
  #     redirection (e.g., display a message during the authorization request).
  #
  #     Lack of transport-layer security can have a severe impact on the
  #     security of the client and the protected resources it is authorized to
  #     access.  The use of transport-layer security is particularly critical
  #     when the authorization process is used as a form of delegated end-user
  #     authentication by the client (e.g., third-party sign-in service).
  #
  SSL_ONLY = True

