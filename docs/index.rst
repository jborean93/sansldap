Sans-IO LDAP: Sans-IO Implementation of the LDAP Protocol
=========================================================

sansldap is an LDAP protocol stack written entirely in Python. The goal of
sansldap is to be a common LDAP library used in the Python ecosystem. It is
designed around the Sans-IO model where the code does not interact with any
I/O mechanisms like sockets, or choose a concurrency model like asyncio. It is
up to the user of this library to focus on the I/O using whatever model that is
desired and leave the protocol implementation details to sansldap.

The following LDAP operations have been implemented:

* Bind
* Extended Requests
* Search Requests

More operations will be added in the future as needed.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   events
   source/modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
