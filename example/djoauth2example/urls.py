# coding: utf-8
from django.conf.urls import patterns, include, url
from django.contrib import admin

from djoauth2.authorization import make_authorization_endpoint


admin.autodiscover()
urlpatterns = patterns('',
    # Admin, for creating new Client and Scope objects.
    url(r'^admin/', include(admin.site.urls)),

    # Used to get User confirmation of Client access requests.
    (r'^oauth2/authorization/$', make_authorization_endpoint(
        missing_redirect_uri='/oauth2/missing_redirect_uri/',
        authorization_endpoint_uri='/oauth2/authorization/',
        authorization_template_name='oauth2server/authorization_page.html')),

    # The page to show when Client redirection URIs are misconfigured or
    # invalid.
    (r'^oauth2/missing_redirect_uri/$', 'oauth2server.views.missing_redirect_uri'),

    # The AccessToken / RefreshToken endpoint logic is handled entirely by the
    # djoauth2 library.
    (r'^oauth2/token/$', 'djoauth2.views.access_token_endpoint'),

    # Our access-protected API endpoint.
    (r'^api/user_info/$', 'api.views.user_info'),
)

