# coding: utf-8
import random
import urlparse
from string import ascii_letters
from string import digits
from urllib import urlencode

# The OAuth 2.0 Bearer specification (
# http://tools.ietf.org/html/rfc6750#section-2.1 ) defines the
# Bearer token syntax as follows:
#
#    b64token    = 1*( ALPHA / DIGIT /
#                      "-" / "." / "_" / "~" / "+" / "/" ) *"="
#    credentials = "Bearer" 1*SP b64token
#
# Because the + and / characters are not URI-safe, we restrict the
# charset to the subset of ( ALPHA / DIGIT / "-" / "." / "_" / "~" ).
BEARER_TOKEN_CHARSET = ascii_letters + digits + '-._~'

# The specification ( http://tools.ietf.org/html/rfc6749#appendix-A.11 ) does
# not provide any limits (VSCHAR). We choose a sane, URI-safe charset.
AUTHORIZATION_CODE_CHARSET = ascii_letters + digits + '-._~'

# The specification ( http://tools.ietf.org/html/rfc6749#appendix-A.1 ) does
# not provide any limits (VSCHAR). We choose a sane, URI-safe charset.
CLIENT_KEY_CHARSET = ascii_letters + digits + '-._~'
CLIENT_SECRET_CHARSET = ascii_letters + digits + '-._~'


def random_string(length, charset):
  return ''.join(random.sample(charset, length))


def make_bearer_token(length):
  return lambda: random_string(length, BEARER_TOKEN_CHARSET)


def make_authorization_code(length):
  return lambda: random_string(length, AUTHORIZATION_CODE_CHARSET)


def make_client_secret(length):
  return lambda: random_string(length, CLIENT_SECRET_CHARSET)


def make_client_key(length):
  return lambda: random_string(length, CLIENT_KEY_CHARSET)


def update_parameters(url, parameters, encoding='utf8'):
  """ Updates a URL's existing GET parameters.

  :param url: a base URL to which to add additional parameters.
  :param parameters: a dictionary of parameters, any mix of
    unicode and string objects as the parameters and the values.
  :parameter encoding: the byte encoding to use when passed unicode
    for the base URL or for keys and values of the parameters dict. This
    isnecessary because `urllib.urlencode` calls the `str()` function on all of
    its inputs.  This raises a `UnicodeDecodeError` when it encounters a
    unicode string with characters outside of the default ASCII charset.
  :rtype: a string URL.
  """
  # Convert  the base URL to the default encoding.
  if isinstance(url, unicode):
    url = url.encode(encoding)

  parsed_url = urlparse.urlparse(url)
  existing_query_parameters = urlparse.parse_qsl(parsed_url.query)

  # Convert unicode parameters to the default encoding.
  byte_parameters = []
  for key, value in (existing_query_parameters + parameters.items()):
    if isinstance(key, unicode):
      key = key.encode(encoding)
    if isinstance(value, unicode):
      value = value.encode(encoding)
    byte_parameters.append((key, value))

  # Generate the final URL with all of the updated parameters. Read
  # http://docs.python.org/2/library/urlparse.html#urlparse.urlparse if this is
  # confusing.
  return urlparse.urlunparse((
      parsed_url.scheme,
      parsed_url.netloc,
      parsed_url.path,
      parsed_url.params,
      urlencode(byte_parameters),
      parsed_url.fragment
    ))

