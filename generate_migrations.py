#!/usr/bin/env python
# coding: utf-8
import sys
from argparse import ArgumentParser
from os.path import abspath
from os.path import dirname

# Modify the path so that our djoauth2 app is in it.
parent_dir = dirname(abspath(__file__))
sys.path.insert(0, parent_dir)

# Load Django-related settings; necessary for tests to run and for Django
# imports to work.
import local_settings

# Now, imports from Django will work properly without raising errors related to
# missing or badly-configured settings.
from django.core import management

from refactor_migrations import refactor


def generate_migrations(initial):
  management.call_command('syncdb', interactive=False)
  if initial:
    management.call_command('schemamigration', 'djoauth2', initial=True)
  else:
    management.call_command('schemamigration', 'djoauth2', auto=True)
  refactor('./djoauth2/migrations/')


def test_migrations():
  management.call_command('syncdb', interactive=False)
  management.call_command('migrate', 'djoauth2')

if __name__ == '__main__':
  parser = ArgumentParser()

  parser.add_argument('--initial-migration',
                      action='store_true',
                      default=False,
                      dest='initial')

  parser.add_argument('--test-migrations',
                      action='store_true',
                      default=False,
                      dest='test_migrations')

  args = parser.parse_args()

  if args.test_migrations:
    test_migrations()
  else:
    generate_migrations(args.initial)




