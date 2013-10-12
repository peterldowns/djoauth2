#!/usr/bin/env python
import os
import sys

def addPath(rel_path, prepend=False):
    """ Adds a directory to the system python path, either by append (doesn't
    override default or globally installed package names) or by prepend
    (overrides default/global package names).
    """
    path = lambda *paths: os.path.abspath(
        os.path.join(os.path.dirname(__file__), *paths)) + '/'
    if prepend:
      return sys.path.insert(0, path(rel_path))
    return sys.path.append(path(rel_path))

# Allow us to not include `djoauth2example` when importing subapps.
addPath('djoauth2example', prepend=True)

# Use the local version of the `djoauth2` library; very useful for manually
# testing the full series of client-server interactions while developing.
addPath('..', prepend=True)

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "djoauth2example.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
