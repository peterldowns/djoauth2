# coding: utf-8
from django.dispatch import Signal

# From http://tools.ietf.org/html/rfc6749#section-10.4 :
#
#     If a refresh token is compromised and subsequently used by both the
#     attacker and the legitimate client, one of them will present an
#     invalidated refresh token, which will inform the authorization server of
#     the breach.
#
# This is the signal raised in that case. You may listen to this signal like
# this:
#
# >>> from django.dispatch import receiver
# >>> from djoauth2.signals import refresh_token_used_after_invalidation
# >>>
# >>> @receiver(refresh_token_used_after_invalidation)
# >>> def invalidated_refresh_token_use_callback(sender, access_token, request):
# >>>   # ... code to alert the client in some way goes here.
# >>>
#
refresh_token_used_after_invalidation = Signal(
    providing_args=['access_token', 'request'])

