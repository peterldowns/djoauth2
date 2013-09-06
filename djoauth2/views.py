# coding: utf-8
import json

from django.http import HttpResponse

from djoauth2.conf import settings
from djoauth2.models import Client, AuthorizationCode, AccessToken, Scope
from djoauth2.exceptions import (InvalidRequest,
                                 AccessTokenException,
                                 UnsupportedGrantType,
                                 InvalidClient,
                                 InvalidGrant,
                                 InvalidScope)

class AccessTokenGenerator(object):
  def __init__(self):
    # Request variables
    self.authorization_code_value = None
    self.client_id = None
    self.client_secret = None
    self.grant_type = None
    self.redirect_uri = None
    self.refresh_token_value = None
    self.scope_names = None
    self.updated_scope_names = None

    # Data set by generate method
    self.client = None

  # ENTRY POINT FOR REQUEST
  def generate(self, request):
    try:
      # Respect TLS settings
      if settings.DJOAUTH_SSL_ONLY and not request.secure():
        raise InvalidRequest('insecure request: must use TLS')

      # Must include client authentication in requests to the token endpoint.
      # http://tools.ietf.org/html/rfc6749#section-3.2.1
      self.client_id = request.POST.get('client_id')
      if not self.client_id:
        raise InvalidRequest('no "client_id" provided')

      try:
        self.client = Client.objects.get(key=self.client_id)
      except Client.DoesNotExist:
        raise InvalidClient('"{}" is not a valid "client_id"'.format(self.client_id))

      self.client_secret = request.POST.get('client_secret')
      if not self.client_secret:
        raise InvalidRequest('no "client_secret" provided"')
      elif not self.client_secret == self.client.secret:
        raise InvalidClient('client authentication failed')
      
      self.grant_type = request.POST.get('grant_type')
      if not self.grant_type:
        raise InvalidRequest('no "grant_type" provided')

      # Either an AuthorizationCode request...
      if self.grant_type == 'authorization_code':
        access_token = self.generate_from_authorization_code(request)
      #... or a RefreshToken request.
      elif self.grant_type == 'refresh_token':
        access_token = self.generate_from_refresh_token(request)
      else:
        raise UnsupportedGrantType('"grant_type" not supported: "{}"'.format(self.grant_type))
      
      # Values taken from http://tools.ietf.org/html/rfc6749#section-5.1
      response_data = {
          'access_token': access_token.value,
          'expires_in': access_token.lifetime,
          # http://tools.ietf.org/html/rfc6749#section-7.1
          'token_type': 'bearer',
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
      # http://tools.ietf.org/html/rfc6749#section-5.2
      self.generation_exception = generation_exception
      error_name = getattr(self.generation_exception,
                           'error_name',
                           'invalid_request')
      error_description = getattr(self.generation_exception,
                                  'message',
                                  'Invalid Request.')
      response_data = {
          'error':  error_name,
          'error_description': error_description,
        }

      response = HttpResponse(content=json.dumps(response_data),
                              content_type='application/json')
      # TODO(peter): update status codes
      if isinstance(self.generation_exception, InvalidClient):
        response.status_code = 401
      else:
        response.status_code = 400

      return response


  def generate_from_authorization_code(self, request):
    # http://tools.ietf.org/html/rfc6749#section-4.1.3
    self.authorization_code_value = request.POST.get('code')
    if not self.authorization_code_value:
      raise InvalidRequest('no "code" provided')

    try:
      self.authorization_code = AuthorizationCode.objects.get(
          value=self.authorization_code_value)
    except AuthorizationCode.DoesNotExist:
      raise InvalidRequest('"{}" is not a valid "code"'.format(self.authorization_code_value))

    if self.authorization_code.is_expired():
      # TODO(peter): is deleting the authorization code the right thing to do?
      self.authorization_code.delete()
      # TODO(peter): invalidate all other tokens granted with this code, if any?
      raise InvalidGrant('provided code is expired')


    # TODO(peter): the spec says that I only need to check if the authorization
    # code request included a redirect_uri parameter. Would it be safe to
    # simply always check, and disallow passing a redirect_uri if one was not
    # passed in the authorization request?
    if (self.authorization_code.redirect_uri and
        self.authorization_code.redirect_uri != request.POST.get('redirect_uri')):
      raise ValueError('"redirect_uri" value must match the value from '
                       'the authorization code request')

    # TODO(peter): should I check that the redirect URI matches the registered
    # client redirect URI?
    
    new_access_token = AccessToken.objects.create(
        user=self.authorization_code.user,
        client=self.authorization_code.client,
        scopes=self.authorization_code.scopes)
    new_access_token.save()
    
    # TODO(peter): is this the right thing to do? Saves DB space, but removes
    # history... maybe we should be able to mark it as 'used' or give it a relationship
    # to the created AccessToken object?
    self.authorization_code.delete()

    return new_access_token
      

  def generate_from_refresh_token(self, request):
    # http://tools.ietf.org/html/rfc6749#section-6
    self.refresh_token_value = request.POST.get('refresh_token')
    if not self.refresh_token_value:
      raise InvalidRequest('no "refresh_token" provided')

    try:
      existing_access_token = AccessToken.objects.get(
          refresh_token=self.refresh_token_value,
          client=self.client)
    except AccessToken.DoesNotExist:
      raise InvalidRequest('"{}" is not a valid "refresh_token"'.format(
        self.refresh_token_value))

    if not existing_access_token.refreshable:
      raise InvalidGrant('access token is not refreshable')

    new_scope_names = request.POST.get('scope', '').split(' ') # OPTIONALLY with more permissions!
    if not existing_access_token.has_scope(*new_scope_names):
      raise InvalidScope('requested scopes exceed initial grant')

    new_scope_objects = []
    for scope_name in new_scope_names:
      try:
        new_scope_objects.append(Scope.objects.get(name=scope_name))
      except Scope.DoesNotExist:
        raise InvalidScope('"{}" is not a valid scope'.format(scope_name))

    new_access_token = AccessToken.objects.create(
        user=existing_access_token.user,
        client=existing_access_token.client,
        scopes=new_scope_objects)
    new_access_token.save()

    existing_access_token.delete()

    return new_access_token


