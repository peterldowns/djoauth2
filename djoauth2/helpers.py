# coding: utf-8
import random
import urlparse
from string import ascii_letters, digits
from urllib import urlencode

# From http://tools.ietf.org/html/rfc6750#section-2.1
BEARER_TOKEN_CHARSET = ascii_letters + digits + '-._~+/'


def random_hash(length):
  return ''.join(random.sample(BEARER_TOKEN_CHARSET, length))


def random_hash_generator(length):
  return lambda: random_hash(length)


def update_parameters(url, parameters):
  """ Updates a URL's existing GET parameters.

  @url: a URL string.
  @parameters: a dictionary of parameters, {string:string}.
  """
  parsed_url = urlparse(url)

  query_parameters = urlparse.parse_qsl(parsed_url.query)
  parsed_url.query = urlencode(query_parameters + parameters.items())

  return urlparse.urlunparse(parsed_url)

