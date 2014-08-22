#!/usr/bin/env python
# coding: utf-8
import json
import requests
from base64 import b64encode

def assert_200(response, max_len=500):
  """ Check that a HTTP response returned 200. """
  if response.status_code == 200:
    return

  raise ValueError(
      "Response was {}, not 200:\n{}\n{}".format(
          response.status_code,
          json.dumps(dict(response.headers), indent=2),
          response.content[:max_len]))

def main():
  client_name = 'Example Client'
  client_key = 'be6f31235c6118273918c4c70f6768'
  client_secret = '89dcee4e6fe655377a19944c2bee9b'
  client_redirect_uri = 'http://localhost:1111/'
  client_auth_headers = {
    'Authorization': 'Basic {}'.format(
        b64encode('{}:{}'.format(client_key, client_secret)))
  }

  authorization_endpoint = 'http://localhost:8080/oauth2/authorization/'
  token_endpoint = 'http://localhost:8080/oauth2/token/'
  user_info_endpoint =   'http://localhost:8080/api/user_info/'

  scopes = ['user_info']
  scope_string = ' '.join(scopes)

  auth_url = '{}?scope={}&client_id={}&response_type=code'.format(
      authorization_endpoint,
      scope_string,
      client_key)

  print ''
  print 'Log in via the admin page (username: exampleuser, password: password)'
  print ''
  print 'http://localhost:8080/admin/'
  print ''
  raw_input('press return to continue...')

  print ''
  print 'Open the following URL in your browser:'
  print ''
  print auth_url
  print ''
  print 'Click the "Accept" button to grant this client access to your data. '
  print 'Your browser will be redirected to a URL with a "code" parameter; copy '
  print 'that value and paste it in below.'
  print ''

  auth_code = raw_input('code=').strip()

  # Exchange the authorization code for an access token.
  data = {
    'code': auth_code,
    'grant_type': 'authorization_code',
  }
  token_response = requests.post(
      token_endpoint,
      data=data,
      headers=client_auth_headers)
  assert_200(token_response)

  token_data = json.loads(token_response.content)
  print ''
  print 'Received access token information:'
  print '   access token:', token_data['access_token']
  print '  refresh token:', token_data.get('refresh_token', '')
  print '   lifetime (s):', token_data['expires_in']
  print ''
  raw_input('press return to continue...')


  # Exchange the refresh token for a new access token, if we received one.
  refresh_token = token_data.get('refresh_token')
  if refresh_token:
    data = {
      'refresh_token' : refresh_token,
      'grant_type' : 'refresh_token',
    }
    token_response = requests.post(
        token_endpoint,
        data=data,
        headers=client_auth_headers,
        verify=False)
    assert_200(token_response)
    token_data = json.loads(token_response.content)

    print ''
    print 'Exchanged refresh token for access token:'
    print '   access token:', token_data['access_token']
    print '  refresh token:', token_data.get('refresh_token', '')
    print '   lifetime (s):', token_data['expires_in']
    print ''
    raw_input('press return to continue...')

  # Make a failing PI request, showing what happens when we don't include
  # authorization.

  failing_api_resp = requests.post(
    user_info_endpoint,
    headers={},
    data={},
    verify=False)

  try:
    assert_200(failing_api_resp)
  except ValueError as ve:
    print 'Unauthenticated API request failed as expected:'
    print ''
    print ve

  # Make an API request, authenticating with our recently received access token.
  api_resp = requests.post(
    user_info_endpoint,
    headers={
      'Authorization': 'Bearer {}'.format(token_data['access_token'])
    },
    data={},
    verify=False)

  assert_200(api_resp)

  print ''
  print 'Authenticated API request succeeded! Returned the following content:'
  print api_resp.content
  print ''

if __name__ == '__main__':
    main()
