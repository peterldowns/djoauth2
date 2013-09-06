# coding: utf-8
import json

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from djoauth2.conf import settings
from djoauth2.exceptions import AccessTokenException
from djoauth2.exceptions import InvalidClient
from djoauth2.exceptions import InvalidGrant
from djoauth2.exceptions import InvalidRequest
from djoauth2.exceptions import InvalidScope
from djoauth2.exceptions import UnsupportedGrantType
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
  """
  try:
    if settings.DJOAUTH_SSL_ONLY and not request.secure():
      raise InvalidRequest('all requests must use TLS')

    # Must include client authentication in requests to the token endpoint.
    # http://tools.ietf.org/html/rfc6749#section-3.2.1
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
    
    # The two supported tyupes
    grant_type = request.POST.get('grant_type')
    if not grant_type:
      raise InvalidRequest('no "grant_type" provided')

    if grant_type == 'authorization_code':
      access_token = generate_access_token_from_authorization_code(request, client)
    elif grant_type == 'refresh_token':
      access_token = generate_access_token_from_authorization_code(request, client)
    else:
      raise UnsupportedGrantType(
          '"{}" is not a supported "grant_type"'.format(grant_type))
    
    # Successful response documentation:
    # http://tools.ietf.org/html/rfc6749#section-5.1
    response_data = {
        'access_token': access_token.value,
        'expires_in': access_token.lifetime,
        'token_type': 'bearer', # http://tools.ietf.org/html/rfc6749#section-7.1
        'scope': ' '.join(access_token.get_scope_name_set()),
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
    error_description = getattr(generation_exception,
                                'message',
                                'Invalid Request.')
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
    raise InvalidGrant('"{}" is not a valid "code"'.format(authorization_code_value))

  if authorization_code.is_expired():
    # TODO(peter): implement an access counter and follow the recommendation
    # of http://tools.ietf.org/html/rfc6749#section-10.5:
    #
    #     If the authorization server observes multiple attempts to exchange an
    #     authorization code for an access token, the authorization server SHOULD
    #     attempt to revoke all access tokens already granted based on the
    #     compromised authorization code.
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
    raise ValueError('"redirect_uri" value must match the value from '
                     'the authorization code request')

  new_access_token = AccessToken.objects.create(
      user=authorization_code.user,
      client=authorization_code.client,
      scopes=authorization_code.scopes)
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
    raise InvalidRequest('"{}" is not a valid "refresh_token"'.format(
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
  # This implementation allows the Client ot request any scopes that together
  # comprise a subset of the previously-granted scopes. The specification
  # does not discuss this particular behavior, but the wording is such that
  # I believe this to be a reasonable behavior. That said, later in the same
  # section the specification includes the following:
  #
  #      If a new refresh token is issued, the refresh token scope MUST be
  #      identical to that of the refresh token included by the client in the
  #      request.
  #
  # I am open to being convinced that allowing scope de-escalation is against
  # the specification, but I cannot see why it would be necessary to forbid
  # it from a security standpoint.
  #
  # TODO(peter): reach a decision regarding this behavior.
  new_scope_names = request.POST.get('scope', '').split(' ')
  if not existing_access_token.has_scope(*new_scope_names):
    raise InvalidScope('requested scopes exceed initial grant')

  new_scope_objects = []
  for scope_name in new_scope_names:
    try:
      new_scope_objects.append(Scope.objects.get(name=scope_name))
    except Scope.DoesNotExist:
      raise InvalidScope('"{}" is not a valid scope'.format(scope_name))

  # The new AccessToken is only refreshable if at the time of refresh the
  # server is configured to create refreshable tokens by default. It DOES NOT
  # inherit the existing token's 'refreshability' automatically. No behavior is
  # described in the specification; I believe this to be a sane decision.
  new_access_token = AccessToken.objects.create(
      user=existing_access_token.user,
      client=existing_access_token.client,
      scopes=new_scope_objects)
  new_access_token.save()

  # TODO(peter): instead of deleting the existing access token / refresh token
  # pair (that was just used to create the new access token), store a reference
  # to the newly created access token and mark the existing token as 'expired'. This
  # allows tokens to remain in the DB for later analysis, but still prevents a
  # refresh token from being used multiple times. In the event that an 'expired'
  # refresh token is used, it would be asy to alert the Client, as recommended by
  # http://tools.ietf.org/html/rfc6749#section-10.4:
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


