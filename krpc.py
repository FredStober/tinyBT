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

import socket, threading, logging
from bencode import bencode, bdecode, BTFailure
from utils import client_version, AsyncResult, AsyncTimeout, encode_uint64, UDPSocket, ThreadManager

krpc_version = bytes(client_version[0] + bytearray([client_version[1], client_version[2]]))

class KRPCError(RuntimeError):
	pass

class KRPCPeer(object):
	def __init__(self, connection, handle_query, cleanup_timeout = 60, cleanup_interval = 10):
		""" Start listening on the connection given by (addr, port)
			Incoming messages are given to the handle_query function,
			with arguments (send_krpc_response, rec).
			send_krpc_response(**kwargs) is a function to send a reply,
			rec contains the dictionary with the incoming message.
		"""
		self._log = logging.getLogger(self.__class__.__name__ + '.%s:%d' % connection)
		self._log_msg = self._log.getChild('msg') # message handling
		self._log_local = self._log.getChild('local') # local queries
		self._log_remote = self._log.getChild('remote') # remote queries
		self._sock = UDPSocket(connection)

		self._transaction = {}
		self._transaction_id = 0
		self._transaction_lock = threading.Lock()
		self._handle_query = handle_query
		self._threads = ThreadManager(self._log)
		self._threads.start_continuous_thread(self._listen)
		self._threads.start_continuous_thread(self._cleanup_transactions,
			thread_interval = cleanup_interval, timeout = cleanup_timeout)

	def send_krpc_query(self, target_connection, method, **kwargs):
		""" Invoke method on the node at target_connection.
			The arguments for the method are given in kwargs.
			Returns an AsyncResult (waitable) that will
			eventually contain the peer response.
		"""
		target_connection = (socket.gethostbyname(target_connection[0]), target_connection[1])
		with self._transaction_lock:
			while True: # Generate transaction id
				self._transaction_id += 1
				local_transaction = bytes(bytearray(encode_uint64(self._transaction_id)).lstrip(b'\x00'))
				if local_transaction not in self._transaction:
					break
			req = {b'y': b'q', b't': local_transaction, b'v': krpc_version, b'q': method, b'a': kwargs}
			result = AsyncResult(source = (method, kwargs, target_connection))
			if not self._threads.shutdown_in_progress():
				if self._log_local.isEnabledFor(logging.INFO):
					self._log_local.info('KRPC request to %r:\n\t%r' % (target_connection, req))
				self._transaction[local_transaction] = result
				self._sock.sendto(bencode(req), target_connection)
			else:
				result.set_result(AsyncTimeout('Shutdown in progress'))
			return result

	def shutdown(self):
		""" This function allows to cleanly shutdown the KRPCPeer. """
		self._threads.shutdown()
		self._sock.close()
		with self._transaction_lock:
			for t in list(self._transaction):
				self._transaction.pop(t).set_result(AsyncTimeout('Shutdown in progress'))
		self._threads.join()

	# Private members #################################################

	def _cleanup_transactions(self, timeout):
		# Remove transactions older than 1min
		with self._transaction_lock:
			timeout_transactions = [t for t, ar in self._transaction.items() if ar.get_age() > timeout]
			if self._log.isEnabledFor(logging.DEBUG):
				self._log.debug('Transactions: %d id=%d timeout=%d' % (len(self._transaction), self._transaction_id, len(timeout_transactions)))
			for t in timeout_transactions:
				self._transaction.pop(t).set_result(AsyncTimeout('Transaction %r: timeout' % t))

	def _listen(self):
		try:
			recv_data = self._sock.recvfrom(timeout = 0.2)
			if not recv_data:
				return
			(encoded_rec, source_connection) = recv_data
			try:
				rec = bdecode(encoded_rec)
			except BTFailure:
				if self._log_msg.isEnabledFor(logging.ERROR):
					self._log_msg.error('Error while parsing KRPC requests from %r:\n\t%r' % (source_connection, encoded_rec))
				return
		except Exception:
			return self._log_msg.exception('Exception while handling KRPC requests from %r:\n\t%r' % (source_connection, encoded_rec))
		try:
			if rec[b'y'] in [b'r', b'e']: # Response / Error message
				t = rec[b't']
				if rec[b'y'] == b'e':
					if self._log_local.isEnabledFor(logging.ERROR):
						self._log_local.error('KRPC error message from %r:\n\t%r' % (source_connection, rec))
					with self._transaction_lock:
						if self._transaction.get(t):
							rec = KRPCError('Error while processing transaction %r:\n\t%r\n\t%r' % (t, rec, self._transaction.get(t).get_source()))
						else:
							rec = KRPCError('Error while processing transaction %r:\n\t%r' % (t, rec))
				else:
					if self._log_local.isEnabledFor(logging.INFO):
						self._log_local.info('KRPC answer from %r:\n\t%r' % (source_connection, rec))
				with self._transaction_lock:
					if self._transaction.get(t):
						self._transaction.pop(t).set_result(rec, source = source_connection)
					elif self._log_local.isEnabledFor(logging.DEBUG):
						self._log_local.debug('Received response from %r without associated transaction:\n%r' % (source_connection, rec))
			elif rec[b'y'] == b'q':
				if self._log_remote.isEnabledFor(logging.INFO):
					self._log_remote.info('KRPC request from %r:\n\t%r' % (source_connection, rec))
				def custom_send_krpc_response(message, top_level_message = {}):
					return self._send_krpc_response(source_connection, rec.pop(b't'), message, top_level_message, self._log_remote)
				self._handle_query(custom_send_krpc_response, rec, source_connection)
			else:
				if self._log_msg.isEnabledFor(logging.ERROR):
					self._log_msg.error('Unknown type of KRPC message from %r:\n\t%r' % (source_connection, rec))
		except Exception:
			self._log_msg.exception('Exception while handling KRPC requests from %r:\n\t%r' % (source_connection, rec))

	def _send_krpc_response(self, source_connection, remote_transaction, message, top_level_message = {}, log = None):
		with self._transaction_lock:
			resp = {b'y': b'r', b't': remote_transaction, b'v': krpc_version, b'r': message}
			resp.update(top_level_message)
			if log == None:
				log = self._log_local
			if log.isEnabledFor(logging.INFO):
				log.info('KRPC response to %r:\n\t%r' % (source_connection, resp))
			self._sock.sendto(bencode(resp), source_connection)


if __name__ == '__main__':
	logging.basicConfig()
	logging.getLogger().setLevel(logging.DEBUG)
	# Implement an echo message
	peer = KRPCPeer(('0.0.0.0', 1111), handle_query = lambda send_krpc_response, rec, source_connection:
		send_krpc_response(message = 'Hello %s!' % rec[b'a'][b'message']))
	query = peer.send_krpc_query(('localhost', 1111), 'echo', message = 'World')
	logging.getLogger().critical('result = %r' % query.get_result(2))
	query1 = peer.send_krpc_query(('localhost', 1111), 'echo', message = 'World')
	peer.shutdown()
	query2 = peer.send_krpc_query(('localhost', 1111), 'echo', message = 'World')
	try:
		query1.get_result()
	except Exception:
		logging.exception('expected query exception')
	try:
		query2.get_result()
	except Exception:
		logging.exception('expected query exception')
