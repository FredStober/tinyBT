"""
The MIT License

Copyright (c) 2014 Fred Stober

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

import sys, select, socket, struct, threading, time, collections, logging

client_version = (b'XK', 0, 0x01) # eXperimental Klient 0.0.1

encode_ip = lambda value: socket.inet_aton(value)
encode_uint16 = lambda value: struct.pack('!H', value)
encode_uint32 = lambda value: struct.pack('!I', value)
encode_uint64 = lambda value: struct.pack('!Q', value)
encode_int32 = lambda value: struct.pack('!i', value)

def encode_connection(con):
	return encode_ip(con[0]) + encode_uint16(con[1])

def encode_nodes(nodes):
	result = b''
	for node in nodes:
		result += bytes(bytearray(node.id).rjust(20, b'\0')) + encode_connection(node.connection)
	return result

decode_ip = lambda value: socket.inet_ntoa(value)
decode_uint16 = lambda value: struct.unpack('!H', value)[0]
decode_uint32 = lambda value: struct.unpack('!I', value)[0]
decode_uint64 = lambda value: struct.unpack('!Q', value)[0]

def decode_connection(con):
	return (decode_ip(con[0:4]), decode_uint16(con[4:6]))

def decode_nodes(nodes):
	try:
		while nodes:
			node_id = struct.unpack('20s', nodes[:20])[0]
			node_connection = decode_connection(nodes[20:26])
			if node_connection[1] >= 1024: # discard invalid port numbers
				yield (node_id, node_connection)
			nodes = nodes[26:]
	except Exception:
		pass # catch malformed nodes

def start_thread(fun, *args, **kwargs):
	thread = threading.Thread(name = repr(fun), target=fun, args=args, kwargs=kwargs)
	thread.daemon = True
	thread.start()
	return thread


class AsyncTimeout(RuntimeError):
	pass


class AsyncResult(object):
	def __init__(self, source = None):
		self._event = threading.Event()
		self._value = None
		self._source = source
		self._time = time.time()

	def get_age(self):
		return time.time() - self._time

	def discard_result(self):
		self._time = 0

	def set_result(self, result, source = None):
		self._value = result
		if source != None:
			self._source = source
		self._event.set()

	def has_result(self):
		return self._event.is_set()

	def get_source(self):
		return self._source

	def get_result(self, timeout = None):
		if not self._event.wait(timeout):
			raise AsyncTimeout
		if isinstance(self._value, Exception):
			raise self._value
		return self._value


class ThreadManager(object):
	def __init__(self, log):
		self._log = log
		self._threads = []
		self._shutdown_event = threading.Event()

	def shutdown_in_progress(self):
		return self._shutdown_event.is_set()

	def shutdown(self):
		self._shutdown_event.set() # Trigger shutdown of threads

	def join(self, timeout = 60):
		self.shutdown()
		for thread in self._threads:
			thread.join(timeout)

	def start_thread(self, name, daemon, fun, *args, **kwargs):
		thread = threading.Thread(name = name, target=fun, args=args, kwargs=kwargs)
		thread.daemon = daemon
		thread.start()
		self._threads.append(thread)
		return thread

	def start_continuous_thread(self, fun, thread_interval = 0, *args, **kwargs):
		if thread_interval >= 0:
			self.start_thread('continuous thread:' + repr(fun), False,
				self._continuous_thread_wrapper, fun, thread_interval = thread_interval, *args, **kwargs)

	def _continuous_thread_wrapper(self, fun, on_except = ['log', 'continue'], thread_waitfirst = False, thread_interval = 0, *args, **kwargs):
		if thread_waitfirst:
			self._shutdown_event.wait(thread_interval)
		while not self._shutdown_event.is_set():
			try:
				fun(*args, **kwargs)
			except Exception:
				if 'log' in on_except:
					self._log.exception('Exception in maintainance thread')
				if 'continue' not in on_except:
					return
			self._shutdown_event.wait(thread_interval)


class NetworkSocket(object):
	def __init__(self, name):
		self._log = logging.getLogger(self.__class__.__name__).getChild(name)
		self._threads = ThreadManager(self._log)
		self._lock = threading.Lock()

		self._send_event = threading.Event()
		self._send_queue = collections.deque()
		self._send_try = 0

		self._recv_event = threading.Event()
		self._recv_queue = collections.deque()

		self._force_show_info = False
		self._threads.start_continuous_thread(self._info_thread, thread_interval = 0.5)
		self._threads.start_continuous_thread(self._send_thread)
		self._threads.start_continuous_thread(self._recv_thread)

	# Non-blocking send
	def sendto(self, *args):
		self._send_queue.append(args)
		with self._lock: # set send flag
			self._send_event.set()

	# Blocking read - with timeout
	def recvfrom(self, timeout = None):
		result = None
		if self._recv_event.wait(timeout):
			if self._recv_queue:
				result = self._recv_queue.pop()
			with self._lock:
				if not self._recv_queue and not self._threads.shutdown_in_progress():
					self._recv_event.clear()
		return result

	def close(self):
		with self._lock:
			self._threads.shutdown()
			self._send_queue.clear()
			self._recv_queue.clear()
			self._send_event.set()
			self._recv_event.set()
		self._close()
		self._threads.join()

	# Private members #################################################

	def _info_thread(self):
		if (len(self._recv_queue) > 20) or (len(self._send_queue) > 20) or self._force_show_info:
			if self._log.isEnabledFor(logging.DEBUG):
				self._log.debug('recv: %4d, send: %4d' % (len(self._recv_queue), len(self._send_queue)))
			self._force_show_info = True
		if not(len(self._recv_queue) or len(self._send_queue)):
			self._force_show_info = False

	def _send_thread(self, send_tries = 100):
		if self._send_event.wait(0.1):
			if self._send_queue:
				if self._send(*self._send_queue[0]):
					self._send_queue.popleft()
					self._send_try = 0
				elif self._send_try > send_tries:
					self._send_queue.popleft()
				else:
					self._send_queue.rotate(-1)
					self._send_try += 1

			with self._lock: # clear send flag
				if not self._send_queue and not self._threads.shutdown_in_progress():
					self._send_event.clear()

	def _send(self, *args):
		raise NotImplemented

	def _recv_thread(self):
		tmp = self._recv()
		if tmp:
			self._recv_queue.append(tmp)
			with self._lock:
				self._recv_event.set()

	def _recv(self):
		raise NotImplemented

	def _close(self):
		raise NotImplemented


class UDPSocket(NetworkSocket):
	def __init__(self, connection):
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self._sock.setblocking(0)
		self._sock.bind(connection)
		NetworkSocket.__init__(self, '%s:%d' % connection)

	def _send(self, *args):
		select.select([], [self._sock], [], 0.1)
		try:
			self._sock.sendto(*args)
			return True
		except socket.error:
			pass

	def _recv(self):
		select.select([self._sock], [], [], 0.1)
		try:
			return self._sock.recvfrom(64*1024)
		except socket.error:
			pass

	def _close(self):
		self._sock.close()
