Steps to get started:

(Optional: create a new virtualenv so that you don't clutter your installs)

1. Install the necessary requirements:

.. code:: bash

  pip install -r requirements.txt

2. Set up the database:

.. code:: bash

  ./manage.py syncdb --no-initial-data

Create a new superuser when prompted to do so – use the username
``exampleuser`` and the password ``password``. Then, install the ``djoauth2``
models:

.. code:: bash

  ./manage.py migrate djoauth2


3. Run the test suite. If they don't all pass, file a bug!

.. code:: bash

  ./manage.py test djoauth2

4. Start the webserver:

.. code:: bash

  ./manage.py runserver 8080

5. Log in to `the admin page <http://localhost:8080/admin/>`_ with the username
   ``exampleuser`` and the password ``password``.

6. Check to make sure that there is a ``DJOAuth2.Client`` by the name of
   ``Example Client`` and  a ``DJOAuth2.Scope`` object by the name of
   ``user_info``.

If you've done all of the above, you're ready to start making requests as a
client — check out the ``client_demo.py`` file for a ready-to-go example!

.. code:: bash

  $ ./client_demo.py

