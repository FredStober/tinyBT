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

import os, time, socket, hashlib, hmac, threading, logging
from bencode import bencode, bdecode
from utils import encode_int, encode_ip, encode_connection, encode_nodes, AsyncTimeout
from utils import decode_int, decode_ip, decode_connection, decode_nodes, start_thread
from krpc import KRPCPeer, KRPCError

# BEP #0042 - prefix is based on ip and last byte of the node id - 21 most significant bits must match
def bep42_prefix(ip, rand_char, rand_rest = '\x00'): # rand_rest determines the last (random) 3 bits
	from crc32c import crc32c
	ip = decode_int(encode_ip(ip))
	value = crc32c(encode_int((ip & 0x030f3fff) | ((ord(rand_char) & 0x7) << 29)))
	return (value & 0xfffff800) | ((ord(rand_rest) << 8) & 0x00000700)

def valid_id(node_id, connection):
	vprefix = bep42_prefix(connection[0], node_id[-1])
	return (((vprefix ^ decode_int(node_id[:4])) & 0xfffff800) == 0)

def strxor(a, b):
	assert(len(a) == len(b))
	return int(a.encode('hex'), 16) ^ int(b.encode('hex'), 16)


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
		self.id_cmp = int(id.encode('hex'), 16)

	def __repr__(self):
		return '%s  %15s  %5d  %20s  %5s  %.2f' % (self.id.encode('hex'), self.connection[0], self.connection[1],
			repr(self.version), valid_id(self.id, self.connection), time.time() - self.last_ping)


# Trivial node list implementation
class DHT_Router(object):
	def __init__(self, name):
		self._log = logging.getLogger(self.__class__.__name__ + '.%s' % name)
		# This is our routing table.
		self._nodes = {}
		self._nodes_lock = threading.Lock()
		self._nodes_protected = set()
		self._connections_bad = set()

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
				if force or ((node.id not in self._nodes_protected) and (node.attempt > 2)):
					if not force:
						self._connections_bad.add(node.connection)
					self._nodes[node.id] = filter(lambda n: n.connection != node.connection, self._nodes[node.id])
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
	def get_nodes(self, N = None, expression = lambda n: True, sorter = None):
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

	def redeem_connections(self, fraction = 0.05):
		remove = int(fraction * len(self._connections_bad))
		with self._nodes_lock:
			while self._connections_bad and (remove > 0):
				self._connections_bad.pop()
				remove -= 1

	def show_status(self):
		with self._nodes_lock:
			self._log.info('Routing table contains %d nodes (%d blacklisted, %s protected)' %\
				(len(self._nodes), len(self._connections_bad), len(self._nodes_protected)))
			if self._log.isEnabledFor(logging.DEBUG):
				for node in self.get_nodes():
					self._log.debug('\t%r' % node)


class DHT(object):
	def __init__(self, listen_connection, bootstrap_connection = ('router.bittorrent.com', 6881), user_setup = {}):
		""" Start DHT peer on given (host, port) and bootstrap connection to the DHT """
		setup = {'report_t': 10, 'check_t': 30, 'check_N': 10, 'discover_t': 180, 'redeem_t': 300}
		setup.update(user_setup)
		self._log = logging.getLogger(self.__class__.__name__ + '.%s.%d' % listen_connection)
		listen_connection = (socket.gethostbyname(listen_connection[0]), listen_connection[1])
		# Generate key for token generation
		self._token_key = os.urandom(20)
		# Start KRPC server process and Routing table
		self._krpc = KRPCPeer(listen_connection, self._handle_query, cleanup_interval = 1)
		self._nodes = DHT_Router('%s.%d' % listen_connection)
		self._node = DHT_Node(listen_connection, os.urandom(20))
		self._node_lock = threading.RLock()
		# Start bootstrap process
		try:
			tmp = self.ping(bootstrap_connection, sender_id = self._node.id).get_result(timeout = 5)
		except Exception:
			tmp = {'ip': encode_connection(listen_connection), 'r': {'id': self._node.id}}
		self._node.connection = decode_connection(tmp['ip'])
		self._bootstrap_node = self._nodes.register_node(bootstrap_connection, tmp['r']['id'])
		# BEP #0042 Enable security extension
		self._node.set_id(encode_int(bep42_prefix(self._node.connection[0], self._node.id[-1], self._node.id[0]))[:3] + self._node.id[3:])
		assert(valid_id(self._node.id, self._node.connection))
		self._nodes.protect_nodes([self._node.id])

		# Start maintainance threads
		self._shutdown_event = threading.Event()
		# Report status of routing table
		self._thread_report = start_thread(self._maintainance_task, self._nodes.show_status,
			interval = setup['report_t'])
		# Periodically ping nodes in the routing table
		def _check_nodes(N):
			check_nodes = list(self._nodes.get_nodes(N, expression = lambda n: (time.time() - n.last_ping > 15*60)))
			if not check_nodes:
				return
			self._log.info('Starting cleanup of known nodes')
			node_result_list = []
			for node in check_nodes:
				node.last_ping = time.time()
				node_result_list.append((node, node.id, self.ping(node.connection, self._node.id)))
			t_end = time.time() + 5
			for (node, node_id, async_result) in node_result_list:
				result = self._eval_dht_response(node, async_result, timeout = max(0, t_end - time.time()))
				if node.id != result.get('id'):
					self._nodes.remove_node(node, force = True)
		self._thread_check = start_thread(self._maintainance_task, _check_nodes,
			interval = setup['check_t'], N = setup['check_N'])
		# Redeem random nodes from the blacklist
		def _redeem():
			self._log.info('Starting redemption of blacklisted nodes')
			self._nodes.redeem_connections()
		self._thread_redeem = start_thread(self._maintainance_task, _redeem, interval = setup['redeem_t'])
		# Try to discover a random node to populate routing table
		def _discover_nodes():
			self._log.info('Starting discovery of random node')
			for idx, entry in enumerate(self.dht_find_node(os.urandom(20))):
				if idx > 10:
					break
		self._thread_discovery = start_thread(self._maintainance_task, _discover_nodes,
			interval = setup['discover_t'])


	def get_external_ip(self):
		return self._node.connection

	def shutdown(self):
		""" This function allows to cleanly shutdown the DHT. """
		self._log.info('shutting down DHT')
		self._shutdown_event.set() # Trigger shutdown of maintainance threads
		while True in map(threading.Thread.is_alive, [self._thread_report, self._thread_check,
				self._thread_redeem, self._thread_discovery]):
			time.sleep(0.1)
		self._krpc.shutdown() # Stop listening for incoming connections

	# Maintainance task
	def _maintainance_task(self, function, interval, **kwargs):
		while interval > 0:
			try:
				function(**kwargs)
			except Exception:
				self._log.exception('Exception in DHT maintenance thread')
			if self._shutdown_event.wait(interval):
				return

	# Handle remote queries
	_reply_handler = {}
	def _handle_query(self, send_krpc_reply, rec, source_connection):
		if self._log.isEnabledFor(logging.DEBUG):
			self._log.debug('handling query from %r: %r' % (source_connection, rec))
		kwargs = rec['a']
		if 'id' in kwargs:
			self._nodes.register_node(source_connection, kwargs['id'], rec.get('v'))
		query = rec['q']
		if query in self._reply_handler:
			send_dht_reply = lambda **kwargs: send_krpc_reply(kwargs,
				# BEP #0042 - require ip field in answer
				{'ip': encode_connection(source_connection)})
			send_dht_reply.connection = source_connection
			self._reply_handler[query](self, send_dht_reply, **kwargs)
		else:
			self._log.error('Unknown request in query %r' % rec)

	# Evaluate async KRPC result and notify the routing table about failures
	def _eval_dht_response(self, node, async_result, timeout):
		try:
			result = async_result.get_result(timeout)
			node.version = result.get('v', node.version)
			self._nodes.good_node(node)
			return result['r']
		except AsyncTimeout: # The node did not reply
			if self._log.isEnabledFor(logging.DEBUG):
				self._log.debug('KRPC timeout %r' % node)
		except KRPCError: # Some other error occured
			self._log.exception('KRPC Error %r' % node)
		self._nodes.remove_node(node)
		async_result.discard_result()
		return {}

	# Iterate KRPC function on closest nodes - query_fun(connection, id, search_value)
	def _iter_krpc_search(self, query_fun, process_fun, search_value, timeout, retries):
		id_cmp = int(search_value.encode('hex'), 16)
		(returned, used_connections, discovered_nodes) = (set(), {}, set())
		while True:
			blacklist_connections = filter(lambda c: used_connections[c] > retries, used_connections)
			discovered_nodes = set(filter(lambda n: n and (n.connection not in blacklist_connections), discovered_nodes))
			close_nodes = set(self._nodes.get_nodes(N = 20,
				expression = lambda n: n.connection not in blacklist_connections,
				sorter = lambda n: n.id_cmp ^ id_cmp))

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
				result = self._eval_dht_response(node, async_result, timeout = max(0, t_end - time.time()))
				with self._node_lock:
					node.pending -= 1
				for node_id, node_connection in decode_nodes(result.get('nodes', '')):
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
	def dht_ping(self, connection, timeout = 1):
		try:
			result = self.ping(connection, self._node.id).get_result(timeout)
			if result.get('r', {}).get('id'):
				self._nodes.register_node(connection, result['r']['id'], result.get('v'))
			return result.get('r', {})
		except (AsyncTimeout, KRPCError):
			pass
	#   (verbatim, async KRPC method)
	def ping(self, target_connection, sender_id):
		return self._krpc.send_krpc_query(target_connection, 'ping', id = sender_id)
	#   (reply method)
	def _ping(self, send_krpc_reply, id, **kwargs):
		send_krpc_reply(id = self._node.id)
	_reply_handler['ping'] = _ping

	# find_node methods
	#   (sync method, iterating on close nodes)
	def dht_find_node(self, search_id):
		def process_find_node(node, result):
			for node_id, node_connection in decode_nodes(result.get('nodes', '')):
				if node_id == search_id:
					yield node_connection
		return self._iter_krpc_search(self.find_node, process_find_node, search_id, timeout = 5, retries = 2)
	#   (verbatim, async KRPC method)
	def find_node(self, target_connection, sender_id, search_id):
		return self._krpc.send_krpc_query(target_connection, 'find_node', id = sender_id, target = search_id)
	#   (reply method)
	def _find_node(self, send_krpc_reply, id, target, **kwargs):
		id_cmp = int(id.encode('hex'), 16)
		send_krpc_reply(id = self._node.id, nodes = encode_nodes(self._nodes.get_nodes(N = 20,
			expression = lambda n: valid_id(n.id, n.connection),
			sorter = lambda n: n.id_cmp ^ id_cmp)))
	_reply_handler['find_node'] = _find_node

	# get_peers methods
	#   (sync method, iterating on close nodes)
	def dht_get_peers(self, info_hash):
		def process_get_peers(node, result):
			if result.get('token'):
				node.tokens[info_hash] = result['token'] # store token for subsequent announce_peer
			for node_connection in map(decode_connection, result.get('values', '')):
				yield node_connection
		return self._iter_krpc_search(self.get_peers, process_get_peers, info_hash, timeout = 5, retries = 2)
	#   (verbatim, async KRPC method)
	def get_peers(self, target_connection, sender_id, info_hash):
		return self._krpc.send_krpc_query(target_connection, 'get_peers', id = sender_id, info_hash = info_hash)
	#   (reply method)
	def _get_peers(self, send_krpc_reply, id, info_hash, **kwargs):
		token = hmac.new(self._token_key, send_krpc_reply.connection[0], hashlib.sha1).digest()
		id_cmp = int(id.encode('hex'), 16)
		reply_args = {'nodes': encode_nodes(self._nodes.get_nodes(N = 8,
			expression = lambda n: valid_id(n.id, n.connection),
			sorter = lambda n: n.id_cmp ^ id_cmp))}
		if self._node.values.get(info_hash):
			reply_args['values'] = map(encode_connection, self._node.values[info_hash])
		send_krpc_reply(id = self._node.id, token = token, **reply_args)
	_reply_handler['get_peers'] = _get_peers

	# announce_peer methods
	#   (sync method, announcing to all nodes giving tokens)
	def dht_announce_peer(self, info_hash):
		for node in self._nodes.get_nodes(expression = lambda n: info_hash in n.tokens):
			yield self.announce_peer(node.connection, self._node.id, info_hash, self._node.connection[1],
				node.tokens[info_hash], implied_port = 1)
	#   (verbatim, async KRPC method)
	def announce_peer(self, target_connection, sender_id, info_hash, port, token, implied_port = None):
		req = {'id': sender_id, 'info_hash': info_hash, 'port': port, 'token': token}
		if implied_port != None: # (optional) "1": port not reliable - remote should use source port
			req['implied_port'] = implied_port
		return self._krpc.send_krpc_query(target_connection, 'announce_peer', **req)
	#   (reply method)
	def _announce_peer(self, send_krpc_reply, id, info_hash, port, token, implied_port = None, **kwargs):
		local_token = hmac.new(self._token_key, send_krpc_reply.connection[0], hashlib.sha1).digest()
		if (local_token == token) and valid_id(id, send_krpc_reply.connection): # Validate token and ID
			if implied_port:
				port = send_krpc_reply.connection[1]
			self._node.values.setdefault(info_hash, []).append((send_krpc_reply.connection[0], port))
			send_krpc_reply(id = self._node.id)
	_reply_handler['announce_peer'] = _announce_peer


if __name__ == '__main__':
	logging.basicConfig()
#	logging.getLogger().setLevel(logging.INFO)
#	logging.getLogger('DHT').setLevel(logging.INFO)
	logging.getLogger('DHT_Router').setLevel(logging.DEBUG)
#	logging.getLogger('KRPCPeer').setLevel(logging.INFO)

	# Create a DHT node
	setup = {'report_t': 5, 'check_t': 2, 'check_N': 10, 'discover_t': 3}
	bootstrap_connection = ('localhost', 10001)
#	bootstrap_connection = ('router.bittorrent.com', 6881)
	dht1 = DHT(('0.0.0.0', 10001), bootstrap_connection, setup)
	dht2 = DHT(('0.0.0.0', 10002), bootstrap_connection, setup)
	dht3 = DHT(('0.0.0.0', 10003), bootstrap_connection, setup)
	dht4 = DHT(('0.0.0.0', 10004), ('localhost', 10003), setup)
	dht5 = DHT(('0.0.0.0', 10005), ('localhost', 10003), setup)
	dht6 = DHT(('0.0.0.0', 10006), ('localhost', 10005), setup)

	print '\nping\n' + '=' * 20 # Ping bootstrap node
	print dht1.dht_ping(bootstrap_connection)
	print dht6.dht_ping(bootstrap_connection)

	print '\nfind_node\n' + '=' * 20 # Search myself
	for node in dht3.dht_find_node(dht1._node.id):
		print '->', node

	print '\nget_peers\n' + '=' * 20 # Search Ubuntu 14.04 info hash
	info_hash = 'cb84ccc10f296df72d6c40ba7a07c178a4323a14'.decode('hex')
	for peer in dht5.dht_get_peers(info_hash):
		print '->', peer

	print '\nannounce_peer\n' + '=' * 20 # Announce availability of info hash at dht5
	print dht5.dht_announce_peer(info_hash)

	print '\nget_peers\n' + '=' * 20
	for peer in dht3.dht_get_peers(info_hash):
		print '->', peer

	print 'done...'
	time.sleep(5*60)
	dht1.shutdown()
	dht6.shutdown()
	print 'shutdown complete'
	time.sleep(60*60)
