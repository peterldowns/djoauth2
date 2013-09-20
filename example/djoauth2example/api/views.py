# coding: utf-8
import json

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from djoauth2.decorators import oauth_scope


@csrf_exempt
@oauth_scope('user_info')
def user_info(access_token, request):
  """ Return basic information about a user.

  Limited to OAuth clients that have receieved authorization to the 'user_info'
  scope.
  """
  user = access_token.user
  data = {
      'username': user.username,
      'first_name': user.first_name,
      'last_name': user.last_name,
      'email': user.email}

  return HttpResponse(content=json.dumps(data),
                      content_type='application/json',
                      status=200)

