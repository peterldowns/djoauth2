# coding: utf-8
import json

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from djoauth2.conf import settings
from djoauth2.exceptions import DJOAuthException
from djoauth2.models import AccessToken
from djoauth2.models import AuthorizationCode
from djoauth2.models import Client
from djoauth2.models import Scope

@csrf_exempt
def access_token_endpoint(request):
  """ Generates AccessTokens if provided with sufficient authorization.

  This endpoint only supports two grant types:
    * authorization_code: http://tools.ietf.org/html/rfc6749#section-4.1
    * refresh_token: http://tools.ietf.org/html/rfc6749#section-6

  For further documentation, read http://tools.ietf.org/html/rfc6749#section-3.2
  """
  try:
    # From http://tools.ietf.org/html/rfc6749#section-3.2 :
    #
    #     Since requests to the token endpoint result in the transmission of
    #     clear-text credentials (in the HTTP request and response), the
    #     authorization server MUST require the use of TLS as described in
    #     Section 1.6 when sending requests to the token endpoint.
    #
    if not request.is_secure():
      raise InvalidRequest('all token requests must use TLS')

    # From http://tools.ietf.org/html/rfc6749#section-3.2 :
    #
    #     The client MUST use the HTTP "POST" method when making access token
    #     requests.
    #
    if not request.method == 'POST':
      raise InvalidRequest('all posts must use POST')

    # TODO(peter): current Client authentication takes place as decribed
    # by the second part of http://tools.ietf.org/html/rfc6749#section-2.3.1 :
    #
    #     Alternatively, the authorization server MAY support including the
    #     client credentials in the request-body using the following parameters:
    #
    #     client_id
    #           REQUIRED.  The client identifier issued to the client during
    #           the registration process described by Section 2.2.
    #
    #     client_secret
    #           REQUIRED.  The client secret.  The client MAY omit the
    #           parameter if the client secret is an empty string.
    #
    #     Including the client credentials in the request-body using the two
    #     parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
    #     to directly utilize the HTTP Basic authentication scheme (or other
    #     password-based HTTP authentication schemes).  The parameters can only
    #     be transmitted in the request-body and MUST NOT be included in the
    #     request URI.
    #
    # which is NOT RECOMMENDED. Instead, the server should implement
    # HTTP Basic Authentication ( http://tools.ietf.org/html/rfc2617#section-2 )
    # as described by http://tools.ietf.org/html/rfc6749#section-2.3.1 :
    #
    #     Clients in possession of a client password MAY use the HTTP Basic
    #     authentication scheme as defined in [RFC2617] to authenticate with
    #     the authorization server.  The client identifier is encoded using the
    #     "application/x-www-form-urlencoded" encoding algorithm per Appendix
    #     B, and the encoded value is used as the username; the client password
    #     is encoded using the same algorithm and used as the password.  The
    #     authorization server MUST support the HTTP Basic authentication
    #     scheme for authenticating clients that were issued a client password.
    #
    # by including an 'Authorization' header like so:
    #
    #      Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
    #
    # where 'czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3' is the result of
    #
    #     base64encode('{client_id}:{client_secret}')
    #

    # TODO(peter): check that 'client_id' and 'client_secret' parameters are
    # not included in the request URI (GET parameters), as specified by
    # http://tools.ietf.org/html/rfc6749#section-2.3.1 :
    #
    #     The parameters can only be transmitted in the request-body and MUST
    #     NOT be included in the request URI.
    #

    # TODO(peter): somehow implement the anti-brute-force requirement specified
    # by http://tools.ietf.org/html/rfc6749#section-2.3.1 :
    #
    #     Since this client authentication method involves a password, the
    #     authorization server MUST protect any endpoint utilizing it against
    #     brute force attacks.
    #

    # TODO(peter): enforce limit to a single authentication method as required
    # by http://tools.ietf.org/html/rfc6749#section-2.3 :
    #
    #     The client MUST NOT use more than one authentication method in each
    #     request.
    #

    # From http://tools.ietf.org/html/rfc6749#section-3.2.1 :
    #
    #     A client MAY use the "client_id" request parameter to identify itself
    #     when sending requests to the token endpoint.  In the
    #     "authorization_code" "grant_type" request to the token endpoint, an
    #     unauthenticated client MUST send its "client_id" to prevent itself
    #     from inadvertently accepting a code intended for a client with a
    #     different "client_id".  This protects the client from substitution of
    #     the authentication code. (It provides no additional security for the
    #     protected resource.)
    #
    client_id = request.POST.get('client_id')
    if not client_id:
      raise InvalidRequest('no "client_id" provided')

    client_secret = request.POST.get('client_secret')
    if not client_secret:
      raise InvalidRequest('no "client_secret" provided"')

    try:
      client = Client.objects.get(key=client_id, secret=client_secret)
    except Client.DoesNotExist:
      raise InvalidClient('client authentication failed')

    # The two supported grant types
    grant_type = request.POST.get('grant_type')
    if not grant_type:
      raise InvalidRequest('no "grant_type" provided')

    if grant_type == 'authorization_code':
      access_token = generate_access_token_from_authorization_code(request,
                                                                   client)
    elif grant_type == 'refresh_token':
      access_token = generate_access_token_from_refresh_token(request, client)
    else:
      raise UnsupportedGrantType(
          '"{}" is not a supported "grant_type"'.format(grant_type))

    # Successful response documentation:
    # http://tools.ietf.org/html/rfc6749#section-5.1
    response_data = {
        'access_token': access_token.value,
        'expires_in': access_token.lifetime,
        'token_type': 'bearer', # http://tools.ietf.org/html/rfc6749#section-7.1
        'scope': ' '.join(access_token.get_scope_names_set()),
      }
    if access_token.refreshable:
      response_data['refresh_token'] = access_token.refresh_token

    response = HttpResponse(content=json.dumps(response_data),
                            content_type='application/json')
    response.status_code = 200
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'
    return response

  except AccessTokenException as generation_exception:
    # Error response documentation:
    # http://tools.ietf.org/html/rfc6749#section-5.2
    error_name = getattr(generation_exception,
                         'error_name',
                         'invalid_request')
    error_description = str(generation_exception) or 'INvalid Request.'
    response_data = {
        'error':  error_name,
        'error_description': error_description,
      }

    response = HttpResponse(content=json.dumps(response_data),
                            content_type='application/json')
    if isinstance(generation_exception, InvalidClient):
      response.status_code = 401
    else:
      response.status_code = 400

    return response


def generate_access_token_from_authorization_code(request, client):
  """ Generates a new AccessToken from a request with an authorization code.

  Read the specification: http://tools.ietf.org/html/rfc6749#section-4.1.3
  """
  authorization_code_value = request.POST.get('code')
  if not authorization_code_value:
    raise InvalidRequest('no "code" provided')

  try:
    authorization_code = AuthorizationCode.objects.get(
        value=authorization_code_value,
        client=client)
  except AuthorizationCode.DoesNotExist:
    raise InvalidGrant(
        '"{}" is not a valid "code"'.format(authorization_code_value))

  if authorization_code.is_expired():
    # TODO(peter): implement an access counter and follow the recommendation
    # of http://tools.ietf.org/html/rfc6749#section-10.5:
    #
    #     If the authorization server observes multiple attempts to exchange an
    #     authorization code for an access token, the authorization server
    #     SHOULD attempt to revoke all access tokens already granted based on
    #     the compromised authorization code.
    #
    raise InvalidGrant('provided "code" is expired')

  # From http://tools.ietf.org/html/rfc6749#section-4.1.3:
  #
  #     redirect_uri
  #         REQUIRED, if the "redirect_uri" parameter was included in the
  #         authorization request as described in Section 4.1.1, and their
  #         values MUST be identical.
  #
  # and later,
  #
  #     The authorization server MUST:
  #
  #     [ ... snip ... ]
  #
  #     o  ensure that the "redirect_uri" parameter is present if the
  #        "redirect_uri" parameter was included in the initial authorization
  #        request as described in Section 4.1.1, and if included ensure that
  #        their values are identical.
  #
  # The 'redirect_uri' attribute of an AuthorizationCode will only be set if
  # the value was included as a parameter during the related authorization
  # request.
  if (authorization_code.redirect_uri and
      authorization_code.redirect_uri != request.POST.get('redirect_uri')):
    raise InvalidRequest('"redirect_uri" value must match the value from '
                         'the authorization code request')

  new_access_token = AccessToken.objects.create(
      user=authorization_code.user,
      client=authorization_code.client)
  new_access_token.scopes = authorization_code.scopes.all()
  new_access_token.save()

  # TODO(peter): instead of deleting the authorization code (making any further
  # attempts to use it fail with a 'Does not exist' error), store a
  # relationship to the created AccessToken object and mark the token as
  # 'expired'. This allows for later rvocation of the AccessToken should there
  # be multiple attempts to re-use this AuthorizationCode.
  authorization_code.delete()

  return new_access_token


def generate_access_token_from_refresh_token(request, client):
  """ Generates a new AccessToken from a request containing a refresh token.

  Read the specification: http://tools.ietf.org/html/rfc6749#section-6.
  """
  refresh_token_value = request.POST.get('refresh_token')
  if not refresh_token_value:
    raise InvalidRequest('no "refresh_token" provided')

  try:
    existing_access_token = AccessToken.objects.get(
        refresh_token=refresh_token_value,
        client=client)
  except AccessToken.DoesNotExist:
    raise InvalidGrant('"{}" is not a valid "refresh_token"'.format(
      refresh_token_value))

  if not existing_access_token.refreshable:
    raise InvalidGrant('access token is not refreshable')

  # The specification (http://tools.ietf.org/html/rfc6749#section-6) describes
  # the scope parameter as follows:
  #
  #     scope
  #           OPTIONAL.  The scope of the access request as described by
  #           Section 3.3.  The requested scope MUST NOT include any
  #           scope not originally granted by the resource owner, and if
  #           omitted is treated as equal to the scope originally granted
  #           by the resource owner.
  #
  # This opens the possibility that a Client might successfully request a
  # subset of the existing scopes, but later in the same section comes the
  # following:
  #
  #      If a new refresh token is issued, the refresh token scope MUST be
  #      identical to that of the refresh token included by the client in the
  #      request.
  #
  # For this reason, the requested scope is required to match the existing scope
  # or not be provided at all.

  scope_objects = existing_access_token.scopes.all()
  new_scope_names = request.POST.get('scope', '')
  if new_scope_names:
    new_scope_names = new_scope_names.split(' ')
    if not existing_access_token.has_scope(*new_scope_names):
      raise InvalidScope('requested scopes exceed initial grant')

    scope_objects = []
    for scope_name in new_scope_names:
      try:
        scope_objects.append(Scope.objects.get(name=scope_name))
      except Scope.DoesNotExist:
        raise InvalidScope('"{}" is not a valid scope'.format(scope_name))

  requested_scope_string = request.POST.get('scope', '')
  if requested_scope_string:
    requested_scope_names = set(requested_scope_string.split(' '))
    if not requested_scope_names == existing_access_token.get_scope_names_set():
      raise InvalidScope('requested scopes do not match initial grant')


  # The new AccessToken is only refreshable if at the time of refresh the
  # server is configured to create refreshable tokens by default. It DOES NOT
  # inherit the existing token's 'refreshability' automatically. No behavior is
  # described in the specification; I believe this to be a sane decision.
  new_access_token = AccessToken.objects.create(
      user=existing_access_token.user,
      client=existing_access_token.client)
  new_access_token.scopes = scope_objects
  new_access_token.save()

  # TODO(peter): instead of deleting the existing access token / refresh token
  # pair (that was just used to create the new access token), store a reference
  # to the newly created access token and mark the existing token as 'expired'.
  # This allows tokens to remain in the DB for later analysis, but still
  # prevents a refresh token from being used multiple times. In the event that
  # an 'expired' refresh token is used, it would be asy to alert the Client, as
  # recommended by http://tools.ietf.org/html/rfc6749#section-10.4 :
  #
  #     For example, the authorization server could employ refresh token
  #     rotation in which a new refresh token is issued with every access token
  #     refresh response.  The previous refresh token is invalidated but
  #     retained by the authorization server.  If a refresh token is
  #     compromised and subsequently used by both the attacker and the
  #     legitimate client, one of them will present an invalidated refresh
  #     token, which will inform the authorization server of the breach.
  #
  existing_access_token.delete()

  return new_access_token


class AccessTokenException(DJOAuthException):
  """ Base class for all AccessToken-related exceptions.

  Read the specification: http://tools.ietf.org/html/rfc6749#section-5.2 .
  """


class InvalidRequest(AccessTokenException):
  """ The request is missing a required parameter, includes an unsupported
  parameter value (other than grant type), repeats a parameter, includes
  multiple credentials, utilizes more than one mechanism for authenticating the
  client, or is otherwise malformed.
  """
  error_name = 'invalid_request'


class InvalidClient(AccessTokenException):
  """ Client authentication failed (e.g., unknown client, no client
  authentication included, or unsupported authentication method). The
  authorization server MAY return an HTTP 401 (Unauthorized) status code to
  indicate which HTTP authentication schemes are supported. If the client
  attempted to authenticate via the "Authorization" request header field, the
  authorization server MUST respond with an HTTP 401 (Unauthorized) status code
  and include the "WWW-Authenticate" response header field matching the
  authentication scheme used by the client.
  """
  error_name = 'invalid_client'


class InvalidGrant(AccessTokenException):
  """ The provided authorization grant (e.g., authorization code, resource
  owner credentials) or refresh token is invalid, expired, revoked, does not
  match the redirection URI used in the authorization request, or was issued to
  another client.
  """
  error_name = 'invalid_grant'


class UnauthorizedClient(AccessTokenException):
  """ The authenticated client is not authorized to use this authorization
  grant type.
  """
  error_name = 'unauthorized_client'


class UnsupportedGrantType(AccessTokenException):
  """ The authorization grant type is not supported by the authorization
  server.
  """
  error_name = 'unsupported_grant_type'


class InvalidScope(AccessTokenException):
  """ The requested scope is invalid, unknown, malformed, or exceeds the scope
  granted by the resource owner.
  """
  error_name = 'invalid_scope'

