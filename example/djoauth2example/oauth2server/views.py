# coding: utf-8
from django.shortcuts import render
from django.http import HttpResponse
from django.forms import Form

def missing_redirect_uri(request):
  """ Display an error message when an authorizaiton request fails and has no
  valid redirect URI.

  The Authorization flow depends on recognizing the Client that is requesting
  certain permissions and redirecting the user back to an endpoint associated
  with the Client.  If no Client can be recognized from the request, or the
  endpoint is invalid for some reason, we redirect the user to a page
  describing that an error has occurred.
  """
  return HttpResponse(content="Missing redirect URI!")

