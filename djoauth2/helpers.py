# coding: utf-8
import random
from string import ascii_letters, digits


# From http://tools.ietf.org/html/rfc6750#section-2.1
BEARER_TOKEN_CHARSET = ascii_letters + digits + '-._~+/'


def random_hash(length):
  return ''.join(random.sample(BEARER_TOKEN_CHARSET, length))

def random_hash_generator(length):
  return lambda: random_hash(length)

