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

The `OAuth website`_ describes OAuth 2.0 as

  An open protocol to allow secure authorization in a simple and standard
  method from web, mobile and desktop applications.

Why use DJOAuth2?
-----------------

In the fall of 2012, when this project began, we read `an article`_ by Daniel
Greenfield (better known as pydanny) criticizing the dearth of high-quality,
open-source OAuth 2.0 provider implementations in Python. The article contains
a wishlist of features for any OAuth implementation:

	• Near turnkey solution
	• Working code (duplicates above bullet but I'm making a point)
	• Working tutorials
	• Documentation
	• Commented code
	• Linted code
	• Test coverage > 80%

This project aims to meet all of these goals, and in particular strives to be:

* Easy to add to existing Django projects, with few dependencies or
  requirements.
* Easy to understand, by virtue of high-quality documentation and examples.
* Functionally compliant with the official specification.
* Sane and secure by default — the specification allows for insecure behavior,
  which has been exploited in many existing implementations by programmers such
  as `Egor Homakov`_.
* Well-documented and commented, in order to make it easy to understand how the
  implementation complies with the specification.
* Well-tested (see the coverage details on the first page of these docs!)

What is implemented?
--------------------

In order to best describe this implementation, we must first describe a few
common terms used in the `OAuth specification`:

	OAuth defines four roles:
	
	   resource owner
	      An entity capable of granting access to a protected resource.
	      When the resource owner is a person, it is referred to as an
	      end-user.
	
	   resource server
	      The server hosting the protected resources, capable of accepting
	      and responding to protected resource requests using access tokens.
	
	   client
	      An application making protected resource requests on behalf of the
	      resource owner and with its authorization.  The term "client" does
	      not imply any particular implementation characteristics (e.g.,
	      whether the application executes on a server, a desktop, or other
	      devices).
	
	   authorization server
	      The server issuing access tokens to the client after successfully
	      authenticating the resource owner and obtaining authorization.

This implementation allows your application to act as a "resource server" and
as an "authorization server". Your application's users are the "resource
owners", and other applications which would like access to your users' data are
the "clients".

The specification describes two `types of clients`_, "confidential" and
"public":

   OAuth defines two client types, based on their ability to authenticate
   securely with the authorization server (i.e., ability to maintain the
   confidentiality of their client credentials):

   confidential
      Clients capable of maintaining the confidentiality of their credentials
      (e.g., client implemented on a secure server with restricted access to
      the client credentials), or capable of secure client authentication using
      other means.

   public
      Clients incapable of maintaining the confidentiality of their credentials
      (e.g., clients executing on the device used by the resource owner, such
      as an installed native application or a web browser-based application),
      and incapable of secure client authentication via any other means.

   The client type designation is based on the authorization server's
   definition of secure authentication and its acceptable exposure levels of
   client credentials.  The authorization server SHOULD NOT make assumptions
   about the client type.

This implementation only supports "confidential" clients. Any web, mobile, or
desktop application that acts as a client must also use some sort of secured
server in order to protect its client credentials. Apps that are entirely
native, or built entirely on the "client-side" of the web, are not supported.

The decisions that are most important to the security of your application are:

* The authorization endpoint will only return authorization codes, which can
  later be exchanged for access tokens.
* Password credentials grants, implicit grants, client credentials grants, and
  all extension grants are not supported.
* Public clients are not supported.
* Every client is required to register its ``redirect_uri``.
* All authorization, token, and API requests are required to use TLS encryption
  in order to prevent credentials from being leaked to a third-party. In
  addition, the registered ``redirect_uri`` must also be secured with TLS. 
* Clients are required to CSRF-protect their redirection endpoints.

These decisions have been made in an attempt to decrease the attack
surface-area of the implementation. The specification has a great overview of
`security considerations`_ that contains reasoning for many of these decisions.

In addition, we only support `Bearer tokens`_ in an effort to make interacting
with the implementation as simple as possible for clients. This means no
fiddling with MAC-signing or hashing!

.. _OAuth 2: http://tools.ietf.org/html/rfc6749
.. _OAuth website: http://oauth.net/
.. _an article: http://pydanny.com/the-sorry-state-of-python-oauth-providers.html
.. _Egor Homakov: http://homakov.blogspot.com/
.. _types of clients: http://tools.ietf.org/html/rfc6749#section-2.1
.. _security considerations: http://tools.ietf.org/html/rfc6749#section-10
.. _Bearer tokens: http://tools.ietf.org/html/rfc6750

