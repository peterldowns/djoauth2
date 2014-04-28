# coding: utf-8
import random

from django.test import TestCase

from djoauth2.helpers import BEARER_TOKEN_CHARSET
from djoauth2.helpers import random_string
from djoauth2.helpers import update_parameters
from urlparse import urlparse
from urlparse import parse_qsl


class TestHelpers(TestCase):
  def test_random_string_not_tied_to_system_random(self):
    """ The random string helper should not use the default source of
    randomness.
    """
    length = 30
    charset = BEARER_TOKEN_CHARSET
    random.seed(1)
    val_1 = random_string(length, BEARER_TOKEN_CHARSET)
    random.seed(1)
    val_2 = random_string(length, BEARER_TOKEN_CHARSET)
    self.assertNotEqual(val_1, val_2)

  def test_update_parameters_adds_params_to_url(self):
    url = 'https://locu.com/'
    parameters = {
        'value1': 'True',
        'value2': '42424242',
        'foo': 'bar',
      }

    updated_url = update_parameters(url, parameters)
    parsed_url = urlparse(updated_url)
    parsed_url_parameters = dict(parse_qsl(parsed_url.query))

    for parameter, value in parameters.iteritems():
      self.assertIn(parameter, parsed_url_parameters)
      self.assertEqual(value, parsed_url_parameters[parameter])


  def test_update_parameters_urlencodes_parameters_as_necessary(self):
    url = 'https://locu.com/'
    parameters = {
        '?': '&',
        '#': 'value',
      }

    updated_url = update_parameters(url, parameters)
    parsed_url = urlparse(updated_url)
    parsed_url_parameters = dict(parse_qsl(parsed_url.query))

    for parameter, value in parameters.iteritems():
      self.assertIn(parameter, parsed_url_parameters)
      self.assertEqual(value, parsed_url_parameters[parameter])

  def test_update_parameters_encodes_unicode_with_encoding(self):
    url = 'https://locu.com/'
    parameters = {
        u'nåme': 'Peter',
        'foo': u'BÅ‰',
      }

    utf8_encoded_parameters = {
        'n\xc3\xa5me': 'Peter',
        'foo': 'B\xc3\x85\xe2\x80\xb0',
      }

    updated_url = update_parameters(url, parameters)
    parsed_url = urlparse(updated_url)
    parsed_url_parameters = dict(parse_qsl(parsed_url.query))

    for parameter, value in utf8_encoded_parameters.iteritems():
      self.assertIn(parameter, parsed_url_parameters)
      self.assertEqual(value, parsed_url_parameters[parameter])

