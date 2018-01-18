import socket
import struct
from json import loads

__version__ = '0.11'

class Monitor:
	def __init__(self, ip, port):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect( (ip, port) )
		self.is_exception = False
		self.known_bb = []

	def __del__(self):
		self.s.close()

	def update_state(self):
		self.s.send("sta")
		if ord( self.s.recv(1)[0] ) == 1:
			self.is_exception = True

	def get_state(self):
		self.update_state()
		return { "is_exception": self.is_exception }

	def reset_coverage(self):
		self.s.send("res")
		self.s.recv(2)

	def get_coverage(self):
		self.s.send("cov")
		
		size = struct.unpack( '<H', self.s.recv(2) )[0]
		data = ''
		while size > 0:
			chunk = self.s.recv(1000)
			size -= len(chunk)
			data += chunk
		
		coverage = loads( data )
		for bb in coverage.keys():
			if not bb in self.known_bb:
				self.known_bb.append(bb)
		return coverage
