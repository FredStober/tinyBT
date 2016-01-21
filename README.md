[![Build Status](https://travis-ci.org/FredStober/tinyBT.svg?branch=master)](https://travis-ci.org/FredStober/tinyBT)
[![Coverage](https://codecov.io/github/FredStober/tinyBT/coverage.svg?branch=master)](https://codecov.io/github/FredStober/tinyBT?branch=master)

tiny Bittorrent client
======================

The goal is to supply an easy to use and simple to understand implementation
of the BitTorrent specifications in python with no external dependencies
except for the python standard library.

The implementation is spread over several files, each implementing
a single component.

  - krpc.py    - implements the basic UDP Kademila-RPC protocol layer
  - dht.py     - contains the code for accessing the Mainline DHT using KRPC


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

DHT Implementation
------------------

The DHT class offers the 4 DHT methods described in BEP #5 - each takes the
remote host in the form of a (host, port) tuple as the first argument. The
other arguments are the same as described in the specification. They all return
an async result holder with the unprocessed data from the remote host:
  - ping(target_connection, sender_id)
  - find_node(target_connection, sender_id, search_id)
  - get_peers(target_connection, sender_id, info_hash)
  - announce_peer(target_connection, sender_id, info_hash, port, token, implied_port = None)

In addition, some additional helper functions are made available - these
functions take care of updating the routing table and are blocking calls with
a user specified timeout:
  - dht_ping(connection, timeout = 5)
      Returns the complete result dictionary of the call.
  - dht_find_node(search_id, timeout = 5, retries = 2)
      Searches iteratively for nodes with the given id
      and yields the connection tuple if found.
  - dht_get_peers(info_hash, timeout = 5, retries = 2)
      Searches iteratively for nodes with the given info_hash
      and yields the connection tuple if found.
  - dht_announce_peer(info_hash, implied_port = 1)
      Registers the availabilty of the info_hash on this node
      to all peers that supplied a token while searching for it.

The final three functions are used to start and shutdown the local DHT Peer
and allow access to the discovered external connection infos:

  - __init__(listen_connection, bootstrap_connection = ('router.bittorrent.com', 6881),
             user_setup = {}, user_router = None)
      The constructor needs to know what address and port to listen on and which node to use
      as a bootstrap node. The run interval and some other parameters of the maintainance
      threads can be configured as well via the user_setup parameter. The default values are:
      {'discover_t': 180, 'check_t': 30, 'check_N': 10}.
      It is possible to provide a user implemntation for the DHT node router with the user_router
      parameter
  - shutdown()
      Start shutdown of the local DHT peer and all associated maintainance threads.
  - get_external_connection()
      Return the discovered external connection infos
