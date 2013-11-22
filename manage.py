#!/usr/bin/env python
# coding: utf-8
import sys
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
from django.conf import settings
from django.core.management import execute_from_command_line

if __name__ == "__main__":

  # If there is a test command, make sure to patch the database settings for
  # South.
  if len(sys.argv) >= 2:
    command = sys.argv[1]
    if command == 'test' and 'south' in settings.INSTALLED_APPS:
      from south.management.commands import patch_for_test_db_setup
      patch_for_test_db_setup()

  sys.exit(execute_from_command_line(sys.argv))

