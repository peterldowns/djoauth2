Steps to get started:

(Optional: create a new virtualenv so that you don't clutter your installs)

1. Install the necessary requirements by running ``pip install -r requirements.txt``

2. Set up database and install fixtures with ``./manage.py syncdb``.

3. Run the test suite with ``./manage.py test djoauth2``. If they don't all pass, file a bug!

4. Start the webserver by running ``./manage.py runserver 8080``

5. Log in to `the admin page <http://localhost:8080/admin/>`_ with the username
   ``exampleuser`` and the password ``password``.

6. Check to make sure that
   there is a ``DJOAuth2.Client`` by the name of ``Example Client`` and  a
   ``DJOAuth2.Scope`` object by the name of ``user_info``. These should have
   been installed by the ``syncdb`` command.

OK, at this point you're ready to start making requests as a client — check out
the ``client_demo.py`` file for a ready-to-go example!

.. code:: bash

  $ ./client_demo.py

