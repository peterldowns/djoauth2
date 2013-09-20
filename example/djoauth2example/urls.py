# coding: utf-8
from django.conf.urls import patterns, include, url
from django.contrib import admin

from djoauth2.authorization import make_authorization_endpoint

admin.autodiscover()

urlpatterns = patterns('',
    # Admin, for creating new Client and Scope objects. You can also create
    # these from the command line but it's easiest from the Admin.
    url(r'^admin/', include(admin.site.urls)),

    # The endpoint for creating and exchanging access tokens and refresh
    # tokens is handled entirely by the djoauth2 library.
    (r'^oauth2/token/$', 'djoauth2.views.access_token_endpoint'),

    # The authorization endpoint, a page where each "resource owner" will
    # be shown the details of the permissions being requested by the
    # "client".
    (r'^oauth2/authorization/$', make_authorization_endpoint(
        # The URI of a page to show when a "client" makes a malformed or
        # insecure request and their registered redirect URI cannot be shown.
        missing_redirect_uri='/oauth2/missing_redirect_uri/',
        # This endpoint's URI.
        authorization_endpoint_uri='/oauth2/authorization/',
        # The name of the template to render to show the "resource owner" the
        # details of the "client's" request.
        authorization_template_name='oauth2server/authorization_page.html')),

    # The page to show when Client redirection URIs are misconfigured or
    # invalid. This should be a nice, simple error page.
    (r'^oauth2/missing_redirect_uri/$', 'oauth2server.views.missing_redirect_uri'),


    # An access-protected API endpoint.
    (r'^api/user_info/$', 'api.views.user_info'),
)

