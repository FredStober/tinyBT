tiny Bittorrent client
======================

The goal is to supply an easy to use and simple to understand implementation
of the BitTorrent specifications in python with no external dependencies
except for the python standard library.

The implementation is spread over several files, each implementing
a single component.

  krpc.py    - implements the basic UDP Kademila-RPC protocol layer


KRPC Implementation
-------------------

The KRPCPeer only exposes three methods:
  - __init__((host, port), query_handler)
      That takes the (host, port) tuple where it should listen and the second
      argument is the function that processes incoming messages.
  - shutdown()
      Shutdown of all threads and connections of the KRPC peer.
  - send_krpc_query((host, port), method, **kwargs)
      This method sends a query to a remote host specified by a (host, pool) tuple.
      The name and arguments to call on the remote host is given as well.
      An async result holder is returned, that allows to wait for a reply.
