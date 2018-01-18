from sys import argv
from json import dumps
import socket
from sys import argv, stdout
import os
from time import sleep
import threading
import struct

__version__ = "0.15"

if os.name == 'posix':
	from sysv_ipc import SharedMemory
	shm_id = argv[1]
	shm_state_id = argv[2]
	shm = shm_w = SharedMemory( int(shm_id) )
	shm_state = SharedMemory( int(shm_state_id) )
else:
	from mmap import mmap, ACCESS_READ, ACCESS_WRITE
	shm_name = argv[1]
	shm_state_name = argv[2]
	shm = mmap(0, 0xffff, shm_name, ACCESS_READ )
	shm_w = mmap(0, 0xffff, shm_name, ACCESS_WRITE )
	shm_state = mmap(0, 10, shm_state_name, ACCESS_READ)


def get_coverage(shm):
	if os.name != 'posix':
		shm.seek(0)
	cur_bytes = shm.read(0xffff)
	coverage = {}
	for i in xrange( len(cur_bytes) ):
		val = ord( cur_bytes[i] )
		if val:
			coverage[i] = val
	return coverage
'''
last_bytes = "\x00" * 0xffff
def get_coverage(shm):
	global last_bytes
	if os.name != 'posix':
		shm.seek(0)
	cur_bytes = shm.read(0xffff)
	coverage = {}
	for i in xrange( len(cur_bytes) ):
		val = ord( cur_bytes[i] ) - ord( last_bytes[i] ) if ord( cur_bytes[i] ) >= ord( last_bytes[i] ) else ord( cur_bytes[i] ) + 0xff - ord( last_bytes[i] )
		if val:
			coverage[i] = val
	last_bytes = cur_bytes
	return coverage
'''
def reset_coverage(shm, size=0xffff):
	if os.name != 'posix':
		shm_w.seek(0)
	shm_w.write("\x00"*size)

def get_state(shm):
	if os.name != 'posix':
		shm.seek(0)
	return shm.read(1)[0]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind( ('0.0.0.0', 31338) )
s.listen(1)

_last_bytes_full = "\x00" * 0xffff
def watch_coverage():
	def _get_coverage(shm):
		if os.name != 'posix':
			shm.seek(0)
		cur_bytes = shm.read(0xffff)
		coverage = {}
		for i in xrange( len(cur_bytes) ):
			val = ord( cur_bytes[i] )
			if val:
				coverage[i] = val
		return coverage

	def _get_coverage_delta(shm):
		global _last_bytes_full
		if os.name != 'posix':
			shm.seek(0)
		cur_bytes = shm.read(0xffff)
		coverage = {}
		for i in xrange( len(cur_bytes) ):
			val = ord( cur_bytes[i] ) - ord( _last_bytes_full[i] ) if ord( cur_bytes[i] ) >= ord( _last_bytes_full[i] ) else ord( cur_bytes[i] ) + 0xff - ord( _last_bytes_full[i] )
			if val:
				coverage[i] = val
		_last_bytes_full = cur_bytes
		return coverage

	known_bb = []
	while True:
		try:
			new_bb = []
			coverage = _get_coverage(shm)
			for bb in coverage.keys():
				if not bb in known_bb:
					known_bb.append(bb)
					new_bb.append(bb)
			if new_bb:
				stdout.write( "new basic blocks in covered zone: %s\n" % ','.join( map( lambda bb: "%d(%d)"%(bb,coverage[bb]), new_bb) ) )
			stdout.write( "executed %d blocks        \r" % len( _get_coverage_delta(shm).keys() ) )
			stdout.flush()
			sleep(1)
		except Exception as e:
			print str(e)
			global _last_bytes_full
			_last_bytes_full = "\x00" * 0xffff
			sleep(1)

t = threading.Thread(target=watch_coverage)
t.start()


while True:
	try:
		c,addr = s.accept()

		while True:
			cmd = c.recv(3)
			if not cmd:
				c.close()
				break

			if cmd == 'cov':
				data = dumps( get_coverage(shm) )
				c.send( struct.pack( '<H', len(data) ) + data )
			elif cmd == 'sta':
				c.send( get_state(shm_state) )
			elif cmd == 'res':
				reset_coverage(shm)
				reset_coverage(shm_state, size=10)
				c.send("ok")
	except Exception as e:
		print str(e)
