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

import socket, struct, threading, time

client_version = ('XK', 0, 0x01) # eXperimental Klient 0.0.1

encode_short = lambda value: struct.pack('!H', value)
encode_int = lambda value: struct.pack('!I', value)
encode_ip = lambda value: socket.inet_aton(value)

def encode_connection(con):
	return encode_ip(con[0]) + encode_short(con[1])

def encode_nodes(nodes):
	result = ''
	for node in nodes:
		result += struct.pack('20s', node.id) + encode_connection(node.connection)
	return result

decode_short = lambda value: struct.unpack('!H', value)[0]
decode_int = lambda value: struct.unpack('!I', value)[0]
decode_ip = lambda value: socket.inet_ntoa(value)

def decode_connection(con):
	return (decode_ip(con[0:4]), decode_short(con[4:6]))

def decode_nodes(nodes):
	while nodes:
		node_id = struct.unpack('20s', nodes[:20])[0]
		node_connection = decode_connection(nodes[20:26])
		yield (node_id, node_connection)
		nodes = nodes[26:]

def start_thread(fun, *args, **kwargs):
	thread = threading.Thread(target=fun, args=args, kwargs=kwargs)
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
