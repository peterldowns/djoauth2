#!/usr/bin/env python
# coding: utf-8
import sys
from os.path import abspath
from os.path import dirname

# Load Django-related settings; necessary for tests to run and for Django
# imports to work.
import local_settings


from django.test.simple import DjangoTestSuiteRunner

def runtests():
    parent_dir = dirname(abspath(__file__))
    sys.path.insert(0, parent_dir)

    test_runner = DjangoTestSuiteRunner(
        verbosity=1,
        interactive=False,
        failfast=False)
    failures = test_runner.run_tests(['djoauth2'])
    sys.exit(failures)

if __name__ == '__main__':
    runtests()
