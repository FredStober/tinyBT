"""
The MIT License

Copyright (c) 2014-2015 Fred Stober

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os, time, socket, hashlib, hmac, threading, logging, random, inspect
from bencode import bencode, bdecode
from utils import encode_uint32, encode_ip, encode_connection, encode_nodes, AsyncTimeout
from utils import decode_uint32, decode_ip, decode_connection, decode_nodes, start_thread, ThreadManager
from krpc import KRPCPeer, KRPCError

# BEP #0042 - prefix is based on ip and last byte of the node id - 21 most significant bits must match
#  * ip = ip address in string format eg. "127.0.0.1"
def bep42_prefix(ip, crc32_salt, first_node_bits): # first_node_bits determines the last 3 bits
	from crc32c import crc32c
	ip_asint = decode_uint32(encode_ip(ip))
	value = crc32c(bytearray(encode_uint32((ip_asint & 0x030f3fff) | ((crc32_salt & 0x7) << 29))))
	return (value & 0xfffff800) | ((first_node_bits << 8) & 0x00000700)

def valid_id(node_id, connection):
	node_id = bytearray(node_id)
	vprefix = bep42_prefix(connection[0], node_id[-1], 0)
	return (((vprefix ^ decode_uint32(node_id[:4])) & 0xfffff800) == 0)

def decode_id(node_id):
	try: # python 3
		return int.from_bytes(node_id, byteorder='big')
	except:
		return int(node_id.encode('hex'), 16)

class DHT_Node(object):
	def __init__(self, connection, id, version = None):
		self.connection = (socket.gethostbyname(connection[0]), connection[1])
		self.set_id(id)
		self.version = version
		self.tokens = {} # tokens to gain write access to self.values
		self.values = {}
		self.attempt = 0
		self.pending = 0
		self.last_ping = 0

	def set_id(self, id):
		self.id = id
		self.id_cmp = decode_id(id)

	def __repr__(self):
		return 'id:%s con:%15s:%-5d v:%20s c:%5s last:%.2f' % (hex(self.id_cmp), self.connection[0], self.connection[1],
			repr(self.version), valid_id(self.id, self.connection), time.time() - self.last_ping)


# Trivial node list implementation
class DHT_Router(object):
	def __init__(self, name, user_setup = {}):
		setup = {'report_t': 10, 'limit_t': 30, 'limit_N': 2000, 'redeem_t': 300, 'redeem_frac': 0.05}
		setup.update(user_setup)

		self._log = logging.getLogger(self.__class__.__name__ + '.%s' % name)
		# This is our (trivial) routing table.
		self._nodes = {}
		self._nodes_lock = threading.RLock()
		self._nodes_protected = set()
		self._connections_bad = set()

		# Start maintainance threads
		self._threads = ThreadManager(self._log.getChild('maintainance'))
		self.shutdown = self._threads.shutdown

		# - Report status of routing table
		def _show_status():
			with self._nodes_lock:
				self._log.info('Routing table contains %d ids with %d nodes (%d bad, %s protected)' %\
					(len(self._nodes), sum(map(len, self._nodes.values())),
					len(self._connections_bad), len(self._nodes_protected)))
				if self._log.isEnabledFor(logging.DEBUG):
					for node in self.get_nodes():
						self._log.debug('\t%r' % node)
		self._threads.start_continuous_thread(_show_status, thread_interval = setup['report_t'], thread_waitfirst = True)
		# - Limit number of active nodes
		def _limit(maxN):
			self._log.debug('Starting limitation of nodes')
			N = len(self.get_nodes())
			if N > maxN:
				for node in self.get_nodes(N - maxN,
						expression = lambda n: n.connection not in self._connections_bad,
						sorter = lambda x: random.random()):
					self.remove_node(node, force = True)
		self._threads.start_continuous_thread(_limit, thread_interval = setup['limit_t'], maxN = setup['limit_N'], thread_waitfirst = True)
		# - Redeem random nodes from the blacklist
		def _redeem_connections(fraction):
			self._log.debug('Starting redemption of blacklisted nodes')
			remove = int(fraction * len(self._connections_bad))
			with self._nodes_lock:
				while self._connections_bad and (remove > 0):
					self._connections_bad.pop()
					remove -= 1
		self._threads.start_continuous_thread(_redeem_connections, thread_interval = setup['redeem_t'], fraction = setup['redeem_frac'], thread_waitfirst = True)


	def protect_nodes(self, node_id_list):
		self._log.info('protect %s' % repr(sorted(node_id_list)))
		with self._nodes_lock:
			self._nodes_protected.update(node_id_list)


	def good_node(self, node):
		with self._nodes_lock:
			node.attempt = 0


	def remove_node(self, node, force = False):
		with self._nodes_lock:
			node.attempt += 1
			if node.id in self._nodes:
				max_attempts = 2
				if valid_id(node.id, node.connection):
					max_attempts = 5
				if force or ((node.id not in self._nodes_protected) and (node.attempt > max_attempts)):
					if not force:
						self._connections_bad.add(node.connection)
					def is_not_removed_node(n):
						return n.connection != node.connection
					self._nodes[node.id] = list(filter(is_not_removed_node, self._nodes[node.id]))
					if not self._nodes[node.id]:
						self._nodes.pop(node.id)


	def register_node(self, node_connection, node_id, node_version = None):
		with self._nodes_lock:
			if node_connection in self._connections_bad:
				if self._log.isEnabledFor(logging.DEBUG):
					self._log.debug('rejected bad connection %s' % repr(node_connection))
				return
			for node in self._nodes.get(node_id, []):
				if node.connection == node_connection:
					if not node.version:
						node.version = node_version
					return node
			if self._log.isEnabledFor(logging.DEBUG):
				self._log.debug('added connection %s' % repr(node_connection))
			node = DHT_Node(node_connection, node_id, node_version)
			self._nodes.setdefault(node_id, []).append(node)
			return node

	# Return nodes matching a filter expression
	def get_nodes(self, N = None, expression = lambda n: True, sorter = lambda n: n.id_cmp):
		if len(self._nodes) == 0:
			raise RuntimeError('No nodes in routing table!')
		result = []
		with self._nodes_lock:
			for id, node_list in self._nodes.items():
				result.extend(filter(expression, node_list))
		result.sort(key = sorter)
		if N == None:
			return result
		return result[:N]


class DHT(object):
	def __init__(self, listen_connection, bootstrap_connection = ('router.bittorrent.com', 6881),
			user_setup = {}, user_router = None):
		""" Start DHT peer on given (host, port) and bootstrap connection to the DHT """
		setup = {'discover_t': 180, 'check_t': 30, 'check_N': 10}
		setup.update(user_setup)
		self._log = logging.getLogger(self.__class__.__name__ + '.%s.%d' % listen_connection)
		self._log.info('Starting DHT node with bootstrap connection %s:%d' % bootstrap_connection)
		listen_connection = (socket.gethostbyname(listen_connection[0]), listen_connection[1])
		# Generate key for token generation
		self._token_key = os.urandom(20)
		# Start KRPC server process and Routing table
		self._krpc = KRPCPeer(listen_connection, self._handle_query)
		if not user_router:
			user_router = DHT_Router('%s.%d' % listen_connection, setup)
		self._nodes = user_router
		self._node = DHT_Node(listen_connection, os.urandom(20))
		self._node_lock = threading.RLock()
		# Start bootstrap process
		try:
			tmp = self.ping(bootstrap_connection, sender_id = self._node.id).get_result(timeout = 1)
		except Exception:
			raise
			tmp = {b'ip': encode_connection(listen_connection), b'r': {b'id': self._node.id}}
		self._node.connection = decode_connection(tmp[b'ip'])
		self._bootstrap_node = self._nodes.register_node(bootstrap_connection, tmp[b'r'][b'id'])
		# BEP #0042 Enable security extension
		local_id = bytearray(self._node.id)
		bep42_value = encode_uint32(bep42_prefix(self._node.connection[0], local_id[-1], local_id[0]))
		self._node.set_id(bep42_value[:3] + self._node.id[3:])
		assert(valid_id(self._node.id, self._node.connection))
		self._nodes.protect_nodes([self._node.id])

		# Start maintainance threads
		self._threads = ThreadManager(self._log.getChild('maintainance'))

		# Periodically ping nodes in the routing table
		def _check_nodes(N, last_ping = 15 * 60, timeout = 5):
			def get_unpinged(n):
				return time.time() - n.last_ping > last_ping
			check_nodes = list(self._nodes.get_nodes(N, expression = get_unpinged))
			if not check_nodes:
				return
			self._log.debug('Starting cleanup of known nodes')
			node_result_list = []
			for node in check_nodes:
				node.last_ping = time.time()
				node_result_list.append((node, node.id, self.ping(node.connection, self._node.id)))
			t_end = time.time() + timeout
			for (node, node_id, async_result) in node_result_list:
				result = self._eval_dht_response(node, async_result, timeout = max(0, t_end - time.time()))
				if result and (node.id != result.get(b'id')): # remove nodes with changing identities
					self._nodes.remove_node(node, force = True)
		self._threads.start_continuous_thread(_check_nodes, thread_interval = setup['check_t'], N = setup['check_N'])

		# Try to discover a random node to populate routing table
		def _discover_nodes():
			self._log.debug('Starting discovery of random node')
			for idx, entry in enumerate(self.dht_find_node(os.urandom(20), timeout = 1)):
				if idx > 10:
					break
		self._threads.start_continuous_thread(_discover_nodes, thread_interval = setup['discover_t'])


	def get_external_connection(self):
		return self._node.connection

	def shutdown(self):
		""" This function allows to cleanly shutdown the DHT. """
		self._log.info('shutting down DHT')
		self._threads.shutdown() # Trigger shutdown of maintainance threads
		self._krpc.shutdown() # Stop listening for incoming connections
		self._nodes.shutdown()
		self._threads.join() # Trigger shutdown of maintainance threads

	# Handle remote queries
	_reply_handler = {}
	def _handle_query(self, send_krpc_reply, rec, source_connection):
		if self._log.isEnabledFor(logging.DEBUG):
			self._log.debug('handling query from %r: %r' % (source_connection, rec))
		try:
			remote_args_dict = rec[b'a']
			if b'id' in remote_args_dict:
				self._nodes.register_node(source_connection, remote_args_dict[b'id'], rec.get(b'v'))
			query = rec[b'q']
			callback = self._reply_handler[query]
			callback_kwargs = {}
			for arg in inspect.getargspec(callback).args[2:]:
				arg_bytes = arg.encode('ascii')
				if arg_bytes in remote_args_dict:
					callback_kwargs[arg] = remote_args_dict[arg_bytes]

			def send_dht_reply(**kwargs):
				# BEP #0042 - require ip field in answer
				return send_krpc_reply(kwargs, {b'ip': encode_connection(source_connection)})
			send_dht_reply.connection = source_connection
			callback(self, send_dht_reply, **callback_kwargs)
		except Exception:
			self._log.exception('Error while processing request %r' % rec)

	# Evaluate async KRPC result and notify the routing table about failures
	def _eval_dht_response(self, node, async_result, timeout):
		try:
			result = async_result.get_result(timeout)
			node.version = result.get(b'v', node.version)
			self._nodes.good_node(node)
			return result[b'r']
		except AsyncTimeout: # The node did not reply
			if self._log.isEnabledFor(logging.DEBUG):
				self._log.debug('KRPC timeout %r' % node)
		except KRPCError: # Some other error occured
			if self._log.isEnabledFor(logging.INFO):
				self._log.exception('KRPC Error %r' % node)
		self._nodes.remove_node(node)
		async_result.discard_result()
		return {}

	# Iterate KRPC function on closest nodes - query_fun(connection, id, search_value)
	def _iter_krpc_search(self, query_fun, process_fun, search_value, timeout, retries):
		id_cmp = decode_id(search_value)
		(returned, used_connections, discovered_nodes) = (set(), {}, set())
		while not self._threads.shutdown_in_progress():
			def above_retries(c):
				return used_connections[c] > retries
			blacklist_connections = set(filter(above_retries, used_connections))
			def valid_node(n):
				return n and (n.connection not in blacklist_connections)
			discovered_nodes = set(filter(valid_node, discovered_nodes))
			def not_blacklisted(n):
				return n.connection not in blacklist_connections
			def sort_by_id(n):
				return n.id_cmp ^ id_cmp
			close_nodes = set(self._nodes.get_nodes(N = 20, expression = not_blacklisted, sorter = sort_by_id))

			if not close_nodes.union(discovered_nodes):
				break

			node_result_list = []
			for node in close_nodes.union(discovered_nodes): # submit all queries at the same time
				if node.pending > 3:
					continue
				if self._log.isEnabledFor(logging.DEBUG):
					self._log.debug('asking %s' % repr(node))
				async_result = query_fun(node.connection, self._node.id, search_value)
				with self._node_lock:
					node.pending += 1
				node_result_list.append((node, async_result))
				used_connections[node.connection] = used_connections.get(node.connection, 0) + 1


			t_end = time.time() + timeout
			for (node, async_result) in node_result_list: # sequentially retrieve results
				if self._threads.shutdown_in_progress():
					break
				result = self._eval_dht_response(node, async_result, timeout = max(0, t_end - time.time()))
				with self._node_lock:
					node.pending -= 1
				for node_id, node_connection in decode_nodes(result.get(b'nodes', b'')):
					discovered_nodes.add(self._nodes.register_node(node_connection, node_id))
				for tmp in process_fun(node, result):
					if tmp not in returned:
						returned.add(tmp)
						yield tmp

	# syncronous query / async reply implementation of BEP #0005 (DHT Protocol) #
	#############################################################################
	# Each KRPC method XYZ is implemented using 3 functions:
	#   dht_XYZ(...) - wrapper to process the result of the KRPC function
	#       XYZ(...) - direct call of the KRPC method - returns AsyncResult
	#      _XYZ(...) - handler to process incoming KRPC calls

	# ping methods
	#   (sync method)
	def dht_ping(self, connection, timeout = 5):
		try:
			result = self.ping(connection, self._node.id).get_result(timeout)
			if result.get(b'r', {}).get(b'id'):
				self._nodes.register_node(connection, result[b'r'][b'id'], result.get(b'v'))
			return result.get(b'r', {})
		except (AsyncTimeout, KRPCError):
			pass
	#   (verbatim, async KRPC method)
	def ping(self, target_connection, sender_id):
		return self._krpc.send_krpc_query(target_connection, b'ping', id = sender_id)
	#   (reply method)
	def _ping(self, send_krpc_reply, id):
		send_krpc_reply(id = self._node.id)
	_reply_handler[b'ping'] = _ping

	# find_node methods
	#   (sync method, iterating on close nodes)
	def dht_find_node(self, search_id, timeout = 5, retries = 2):
		def process_find_node(node, result):
			for node_id, node_connection in decode_nodes(result.get(b'nodes', b'')):
				if node_id == search_id:
					yield node_connection
		return self._iter_krpc_search(self.find_node, process_find_node, search_id, timeout, retries)
	#   (verbatim, async KRPC method)
	def find_node(self, target_connection, sender_id, search_id):
		return self._krpc.send_krpc_query(target_connection, b'find_node', id = sender_id, target = search_id)
	#   (reply method)
	def _find_node(self, send_krpc_reply, id, target):
		id_cmp = decode_id(id)
		def select_valid(n):
			return valid_id(n.id, n.connection)
		def sort_by_id(n):
			return n.id_cmp ^ id_cmp
		send_krpc_reply(id = self._node.id, nodes = encode_nodes(self._nodes.get_nodes(N = 20,
			expression = select_valid, sorter = sort_by_id)))
	_reply_handler[b'find_node'] = _find_node

	# get_peers methods
	#   (sync method, iterating on close nodes)
	def dht_get_peers(self, info_hash, timeout = 5, retries = 2):
		def process_get_peers(node, result):
			if result.get(b'token'):
				node.tokens[info_hash] = result[b'token'] # store token for subsequent announce_peer
			for node_connection in map(decode_connection, result.get(b'values', b'')):
				yield node_connection
		return self._iter_krpc_search(self.get_peers, process_get_peers, info_hash, timeout, retries)
	#   (verbatim, async KRPC method)
	def get_peers(self, target_connection, sender_id, info_hash):
		return self._krpc.send_krpc_query(target_connection, b'get_peers', id = sender_id, info_hash = info_hash)
	#   (reply method)
	def _get_peers(self, send_krpc_reply, id, info_hash):
		token = hmac.new(self._token_key, encode_ip(send_krpc_reply.connection[0]), hashlib.sha1).digest()
		id_cmp = decode_id(id)
		def select_valid(n):
			return valid_id(n.id, n.connection)
		def sort_by_id(n):
			return n.id_cmp ^ id_cmp
		reply_args = {'nodes': encode_nodes(self._nodes.get_nodes(N = 8, expression = select_valid, sorter = sort_by_id))}
		if self._node.values.get(info_hash):
			reply_args['values'] = list(map(encode_connection, self._node.values[info_hash]))
		send_krpc_reply(id = self._node.id, token = token, **reply_args)
	_reply_handler[b'get_peers'] = _get_peers

	# announce_peer methods
	#   (sync method, announcing to all nodes giving tokens)
	def dht_announce_peer(self, info_hash, implied_port = 1):
		def has_info_hash_token(node):
			return info_hash in node.tokens
		for node in self._nodes.get_nodes(expression = has_info_hash_token):
			yield self.announce_peer(node.connection, self._node.id, info_hash, self._node.connection[1],
				node.tokens[info_hash], implied_port = implied_port)
	#   (verbatim, async KRPC method)
	def announce_peer(self, target_connection, sender_id, info_hash, port, token, implied_port = None):
		req = {'id': sender_id, 'info_hash': info_hash, 'port': port, 'token': token}
		if implied_port != None: # (optional) "1": port not reliable - remote should use source port
			req['implied_port'] = implied_port
		return self._krpc.send_krpc_query(target_connection, b'announce_peer', **req)
	#   (reply method)
	def _announce_peer(self, send_krpc_reply, id, info_hash, port, token, implied_port = None):
		local_token = hmac.new(self._token_key, encode_ip(send_krpc_reply.connection[0]), hashlib.sha1).digest()
		if (local_token == token) and valid_id(id, send_krpc_reply.connection): # Validate token and ID
			if implied_port:
				port = send_krpc_reply.connection[1]
			self._node.values.setdefault(info_hash, []).append((send_krpc_reply.connection[0], port))
			send_krpc_reply(id = self._node.id)
	_reply_handler[b'announce_peer'] = _announce_peer


if __name__ == '__main__':
	logging.basicConfig()
	log = logging.getLogger()
	log.setLevel(logging.INFO)
	logging.getLogger('DHT').setLevel(logging.INFO)
	logging.getLogger('DHT_Router').setLevel(logging.ERROR)
	logging.getLogger('KRPCPeer').setLevel(logging.ERROR)
	logging.getLogger('KRPCPeer.local').setLevel(logging.ERROR)
	logging.getLogger('KRPCPeer.remote').setLevel(logging.ERROR)

	# Create a DHT swarm
	setup = {}
	bootstrap_connection = ('localhost', 10001)
#	bootstrap_connection = ('router.bittorrent.com', 6881)
	dht1 = DHT(('0.0.0.0', 10001), bootstrap_connection, setup)
	dht2 = DHT(('0.0.0.0', 10002), bootstrap_connection, setup)
	dht3 = DHT(('0.0.0.0', 10003), bootstrap_connection, setup)
	dht4 = DHT(('0.0.0.0', 10004), ('localhost', 10003), setup)
	dht5 = DHT(('0.0.0.0', 10005), ('localhost', 10003), setup)
	dht6 = DHT(('0.0.0.0', 10006), ('localhost', 10005), setup)

	log.critical('starting "ping" test')
	log.critical('ping: dht1 -> bootstrap = %r' % dht1.dht_ping(bootstrap_connection))
	log.critical('ping: dht6 -> bootstrap = %r' % dht6.dht_ping(bootstrap_connection))

	log.critical('starting "find_node" test')
	for idx, node in enumerate(dht3.dht_find_node(dht1._node.id)):
		log.critical('find_node: dht3 -> id(dht1) result #%d: %s:%d' % (idx, node[0], node[1]))
		if idx > 10:
			break

	import binascii
	info_hash = binascii.unhexlify('ae3fa25614b753118931373f8feae64f3c75f5cd') # Ubuntu 15.10 info hash

	log.critical('starting "get_peers" test')
	for idx, peer in enumerate(dht5.dht_get_peers(info_hash)):
		log.critical('get_peers: dht5 -> info_hash result #%d: %r' % (idx, peer))

	log.critical('starting "announce_peer" test')
	for idx, async_result in enumerate(dht5.dht_announce_peer(info_hash)):
		log.critical('announce_peer: dht2 -> close_nodes(info_hash) #%d: %r' % (idx, async_result.get_result(1)))

	log.critical('starting "get_peers" test')
	for idx, peer in enumerate(dht1.dht_get_peers(info_hash)):
		log.critical('get_peers: dht1 -> info_hash result #%d: %r' % (idx, peer))

	for dht in [dht1, dht2, dht3, dht4, dht5, dht6]:
		dht.shutdown()
