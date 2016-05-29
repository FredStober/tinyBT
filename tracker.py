"""
The MIT License

Copyright (c) 2015 Fred Stober

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

import sys, socket, random
from bencode import bdecode
from utils import UDPSocket, encode_int32, decode_connection
from utils import encode_ip, encode_uint64, encode_uint32, encode_uint16
from utils import decode_ip, decode_uint64, decode_uint32

class TrackerException(Exception):
	pass

if sys.version_info[0] >= 3:
	import urllib.request, urllib.parse, urllib.error, urllib.parse
	def parse_url(url):
		return urllib.parse.urlparse(url)
	def open_url(tracker_url, query):
		url = tracker_url + '?' + urllib.parse.urlencode(list(query.items()))
		return urllib.request.urlopen(url)
else:
	import urllib, urlparse
	def parse_url(url):
		return urlparse.urlparse(url)
	def open_url(tracker_url, query):
		url = tracker_url + '?' + urllib.urlencode(query.items())
		return urllib.urlopen(url)

def decode_connections(data):
	while len(data) >= 6:
		c = decode_connection(data[0:6])
		if c[1] >= 1024:
			yield c
		data = data[6:]

# Implementation of BEP #0015 (UDP tracker protocol)
def udp_get_peers(tracker_url, info_hash, peer_id, ip = '0.0.0.0', port = 0,
		uploaded = 0, downloaded = 0, left = 0, event = 'started', num_want = -1, key = 0):
	event = {'empty': 0, 'completed': 1, 'started': 2, 'stopped': 3}[event]
	url = parse_url(tracker_url)
	conn = (socket.gethostbyname(url.hostname), url.port)
	sock = UDPSocket(('0.0.0.0', 0))

	def recv():
		timeout = 5
		while True:
			try:
				data, src = sock.recvfrom(timeout)
			except:
				data = None
			if not data:
				timeout *= 2
				if timeout > 60:
					break
				continue
			try:
				assert(len(data) >= 16)
				action = decode_uint32(data[0:4])
				remote_tid = decode_uint32(data[4:8])
				return (action, remote_tid, data[8:])
			except:
				raise
		return (None, None, None)

	def perform_announce():
		cid = 0x41727101980

		action_connect = 0
		tid = random.randint(0, 2**32-1)
		remote_tid = None
		while remote_tid != tid:
			req = encode_uint64(cid) + encode_uint32(action_connect) + encode_uint32(tid)
			sock.sendto(req, conn)
			(action, remote_tid, data) = recv()
			if not data:
				raise TrackerException('Tracker %s:%d did not answer to handshake' % conn)
			remote_cid = decode_uint64(data[0:8])
			if action != action_connect:
				remote_tid = None

		action_announce = 1
		tid = random.randint(0, 2**32-1)
		remote_tid = None
		while remote_tid != tid:
			assert(len(info_hash) == 20)
			assert(len(peer_id) == 20)
			req = encode_uint64(remote_cid) + encode_uint32(action_announce) + encode_uint32(tid) + \
				info_hash + peer_id + \
				encode_uint64(downloaded) + encode_uint64(left) + encode_uint64(uploaded) + \
				encode_uint32(event) + encode_ip(ip) + encode_uint32(key) + encode_int32(num_want) + encode_uint16(port)
			sock.sendto(req, conn)
			(action, remote_tid, data) = recv()
			if not data:
				raise TrackerException('Tracker %s:%d did not answer to query' % conn)
			if action != action_announce:
				remote_tid = None

		interval = decode_uint32(data[0:4])
		num_leech = decode_uint32(data[4:8])
		num_seed = decode_uint32(data[8:12])
		return list(decode_connections(data[12:]))

	try:
		return perform_announce()
	finally:
		sock.close()

# Implementation of BEP #0003 (Bittorrent - section: HTTP Tracker protocol)
def http_get_peers(tracker_url, info_hash, peer_id, ip = '0.0.0.0', port = 0,
		uploaded = 0, downloaded = 0, left = 0, event = 'started'):
	query = {b'info_hash': info_hash, b'peer_id': peer_id, b'ip': ip, b'port': port,
		b'uploaded': uploaded, b'downloaded': downloaded, b'left': left, b'compact': 1}
	if event:
		query['event'] = event
	handle = open_url(tracker_url, query)
	if handle.getcode() == 200:
		decoded = bdecode(handle.read())
		if not b'peers' in decoded:
			raise TrackerException(decoded.get(b'failure reason', 'Unknown failure'))
		return list(decode_connections(decoded.get(b'peers', '')))

if __name__ == '__main__':
	import os, binascii, logging
	peer_id = os.urandom(20)
	info_hash = binascii.unhexlify('ae3fa25614b753118931373f8feae64f3c75f5cd') # Ubuntu 15.10 info hash
	try:
		print(http_get_peers('http://torrent.ubuntu.com:6969/announce', info_hash, peer_id))
	except Exception:
		logging.exception('Exception during http query')
	try:
		print(udp_get_peers('udp://tracker.coppersurfer.tk:6969', info_hash, peer_id))
	except Exception:
		logging.exception('Exception during udp query')
