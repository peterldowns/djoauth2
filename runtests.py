#!/usr/bin/env python
# coding: utf-8
import sys
from argparse import ArgumentParser
from os.path import abspath
from os.path import dirname

# Load Django-related settings; necessary for tests to run and for Django
# imports to work.
import local_settings
# Now, imports from Django will work properly without raising errors related to
# missing or badly-configured settings.

from django.test.simple import DjangoTestSuiteRunner

def runtests(verbosity, failfast, interactive, test_labels):
  # Modify the path so that our djoauth2 app is in it.
  parent_dir = dirname(abspath(__file__))
  sys.path.insert(0, parent_dir)

  test_runner = DjangoTestSuiteRunner(
      verbosity=verbosity,
      interactive=interactive,
      failfast=failfast)

  sys.exit(test_runner.run_tests(test_labels))

if __name__ == '__main__':
  # Parse any command line arguments.
  parser = ArgumentParser()
  parser.add_argument('--failfast',
                      action='store_true',
                      default=False,
                      dest='failfast')
  parser.add_argument('--interactive',
                      action='store_true',
                      default=False,
                      dest='interactive')
  parser.add_argument('--verbosity', default=1, type=int)
  parser.add_argument('test_labels', nargs='*', default=('djoauth2',))

  args = parser.parse_args()

  # Run the tests.
  runtests(args.verbosity, args.failfast, args.interactive, args.test_labels)
