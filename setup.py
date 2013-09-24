# coding: utf-8
import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()
REQUIREMENTS = [
    line.strip() for line in open(os.path.join(os.path.dirname(__file__),
                                               'requirements.txt')).readlines()]

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='djoauth2',
    version='0.2.1',
    packages=['djoauth2', 'djoauth2.tests'],
    include_package_data=True,
    license='MIT License',
    description='OAuth 2.0 server implementation.',
    long_description=README,
    url='https://github.com/peterldowns/djoauth2/',
    download_url='https://github.com/peterldowns/djoauth2/tarball/0.2.1',
    keywords=['oauth', 'oauth2', 'django'],
    install_requires=REQUIREMENTS,
    author='Peter Downs',
    author_email='peterldowns@gmail.com',
    classifiers=[
          'Environment :: Web Environment',
          'Framework :: Django',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
    ],
)

