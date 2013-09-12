from django.conf.urls.defaults import *

urlpatterns = patterns('djoauth2.views',
    (r'^oauth2/token', 'access_token_endpoint'),
)

