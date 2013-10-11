# coding: utf-8
from django.shortcuts import render
from django.http import HttpResponse
from django.forms import Form

from djoauth2.authorization import make_authorization_endpoint


def missing_redirect_uri(request):
  """ Display an error message when an authorization request fails and has no
  valid redirect URI.

  The Authorization flow depends on recognizing the Client that is requesting
  certain permissions and redirecting the user back to an endpoint associated
  with the Client.  If no Client can be recognized from the request, or the
  endpoint is invalid for some reason, we redirect the user to a page
  describing that an error has occurred.
  """
  return HttpResponse(content="Missing redirect URI!")

authorization_endpoint = make_authorization_endpoint(
  # The URI of a page to show when a "client" makes a malformed or insecure
  # request and their registered redirect URI cannot be shown.  In general, it
  # should simply show a nice message describing that an error has occurred;
  # see the view definition above for more information.
  missing_redirect_uri='/oauth2/missing_redirect_uri/',

  # This endpoint is being dynamically constructed, but it also needs to know
  # the URI at which it is set up so that it can create forms and handle
  # redirects, so we explicitly pass it the URI.
  authorization_endpoint_uri='/oauth2/authorization/',

  # The name of the template to render to show the "resource owner" the details
  # of the "client's" request. See the documentation for more details on the
  # context used to render this template.
  authorization_template_name='oauth2server/authorization_page.html')

