DJOAuth2
========

.. image:: https://badge.fury.io/py/djoauth2.png
    :target: https://pypi.python.org/pypi/djoauth2

.. image:: https://travis-ci.org/Locu/djoauth2.png?branch=master
    :target: https://travis-ci.org/Locu/djoauth2

* Source code: https://github.com/locu/djoauth2
* Documentation: http://djoauth2.readthedocs.org/
* Issue tracker: https://github.com/locu/djoauth2/issues
* Mailing list: https://groups.google.com/forum/#!forum/djoauth2

What is DJOAuth2?
-----------------

DJOAuth2 is an implementation of a *sane* subset of the `OAuth 2`_
specification, which is described by the `OAuth Website`_ as

  An open protocol to allow secure authorization in a simple and standard
  method from web, mobile and desktop applications.


The goal of this implementation is to provide a well-structured Django
application that can be easily installed to add OAuth 2.0 provider capability to
existing projects. The official specification is broad, and allows for
many different ways for clients and servers to interact with each other. This
implementation is a secure subset of these interactions in order to make it as
easy as possible to reap the benefits of OAuth without having to struggle with
the more difficult parts of the spec.

OAuth, and this implementation, are best suited to solving the following
problems:

* Allowing for fine-grained API control — you want your users to choose which
  applications have access to their data.
* Acting as an authentication server, allowing other sites to "Log in with
  <your app>".

Contributing
------------

Interested in contributing? Great! Check out `the contribution guide`_, which
includes instructions for setting up dependencies, generating migrations, and
running the test suite.


.. _`OAuth 2`: http://tools.ietf.org/html/rfc6749
.. _`OAuth website`: http://oauth.net/
.. _`the contribution guide`: http://djoauth2.readthedocs.org/en/latest/contributing.html

