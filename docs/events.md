# LDAP Events

Here are some common scenarios in the LDAP protocol and how they can be implemented with this library.
The examples here are all based on an IO-less connection, this layer still needs to be provided by a higher layer.

## Authentication

Authentication with LDAP falls into two different categories:

* Simple binds
* SASL binds

A simple bind works by providing the username and password in plaintext to be sent to the server.
Simple binds do not support message encryption and typically rely on the outer transport to encrypt the data, for example through TLS.
An example simple bind in Python looks like:

```python
import sansldap

client = sansldap.LDAPClient()
server = sansldap.LDAPServer()

client.bind_simple("username", "password")
client_outgoing = client.data_to_send()

bind_request = server.receive(client_outgoing)[0]
assert isinstance(bind_request, sansldap.BindRequest)
assert isinstance(bind_request.authentication, sansldap.SimpleCredential)
assert bind_request.name == "username"
assert bind_request.authentication.password == "password"

# Can specify an error code on a faulty bind.
server.bind_response(bind_request.message_id)
server_outgoing = server.data_to_send()

bind_response = client.receive(server_outgoing)[0]
assert isinstance(bind_response, sansldap.BindResponse)
assert bind_response.result.result_code == sansldap.LDAPResultCode.SUCCESS
```

A SASL bind is more complex and is designed to encapulsate credential blobs from other providers, like GSSAPI, as part of the bind operation.
A SASL bind can require multiple messages to complete the request and the number of payloads is dependent on the SASL mechanism used.
SASL examples can be found in [sasl.py](https://github.com/jborean93/sansldap/tests/examples/sasl.py).

### Exchanged Messages

|Message|Source|Purpose|
|-|-|-|
|[BindRequest](./source/sansldap.html#sansldap.BindRequest)|Client|Starts the bind request|
|[BindResponse](./source/sansldap.html#sansldap.BindResponse)|Server|Server's response to the bind request|

## Search Request

A search request is performed to search the LDAP database for specific entries.
See [LDAPClient.search_reqest](./source/sansldap.html#sansldap.LDAPClient.search_request) for more information on the parameters that a client can provide on a search request.
During the search request the server can send a `SearchResultEntry`, `SearchResultReference`, or a `SearchResultDone` message using the same message id from the `SearchRequest.
The `SearchResultDone` message should be the last message for the operation and indicates the server will send no more results for this operation.
An example of a search request operation is:

```python
import sansldap

client = sansldap.LDAPClient()
server = sansldap.LDAPServer()

# Client most likely needs to be bound before the search

# There are more options that can be provided for a request.
client.search_request("", attributes=["defaultNamingContext"])
client_outgoing = client.data_to_send()

search_request = server.receive(client_outgoing)[0]
assert isinstance(search_request, sansldap.SearchRequest)
assert search_request.base_object == ""
assert search_request.attributes == ["defaultNamingContext"]

server.search_result_entry(
    search_request.message_id,
    search_request.base_object,
    attributes=[
        sansldap.PartialAttribute("defaultNamingContext", [b"DC=domain,DC=test"]),
    ],
)
server.search_result_done(search_request.message_id)
server_outgoing = server.data_to_send()

responses = client.receive(server_outgoing)
assert len(responses) == 2
assert isinstance(responses[0], sansldap.SearchResultEntry)
assert isinstance(responses[1], sansldap.SearchResultDone)

assert len(responses[0].attributes) == 1
assert responses[0].attributes[0].name == "defaultNamingContext"
assert responses[0].attributes[0].values == [b"DC=domain,DC=test"]
assert responses[1].result.result_code == sansldap.LDAPResultCode.SUCCESS
```

### Exchanged Messages

|Message|Source|Purpose|
|-|-|-|
|[SearchRequest](./source/sansldap.html#sansldap.SearchRequest)|Client|Initiates the search operation|
|[SearchResultEntry](./source/sansldap.html#sansldap.SearchResultEntry)|Server|A search result|
|[SearchResultReference](./source/sansldap.html#sansldap.SearchResultReference)|Server|A reference was encountered for a dataset in another server|
|[SearchResultDone](./source/sansldap.html#sansldap.SearchResultDone)|Server|The search operation is complete|

## StartTLS

A StartTLS operation is used to wrap an LDAP connection over port 389 in a TLS channel.
It is also known as explicit TLS and while most implementations recommend using LDAPS over port 686, StartTLS may be required by the server.
Performing a StartTLS operation is done by sending an ExtendedRequest, waiting for the ExtendedResponse, and then changing the transport channel to TLS wrap the messages.
An example of a StartTLS operation is:

```python
import sansldap

client = sansldap.LDAPClient()
server = sansldap.LDAPServer()

client.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS.value)
client_outgoing = client.data_to_send()

ext_request = server.receive(client_outgoing)[0]
assert isinstance(ext_request, sansldap.ExtendedRequest)
assert ext_request.name == sansldap.ExtendedOperations.LDAP_START_TLS.value

server.extended_response(ext_request.message_id)
server_outgoing = server.data_to_send()

ext_response = client.receive(server_outgoing)[0]
assert isinstance(ext_response, sansldap.ExtendedResponse)
assert ext_response.result.result_code == sansldap.LDAPResultCode.SUCCESS

# The TLS handshake needs to be performed on the socket to set up the TLS
# channel. Any future messages to send from data_to_send() needs to be wrapped
# by the TLS channel that was set up.
```

### Exchanged Messages

|Message|Source|Purpose|
|-|-|-|
|[ExtendedRequest](./source/sansldap.html#sansldap.ExtendedRequest)|Client|Starts the StartTLS operation|
|[ExtendedResponse](./source/sansldap.html#sansldap.ExtendedResponse)|Server|Server's response to the StartTLS request|
