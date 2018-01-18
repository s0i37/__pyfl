from os import path
import socket
from sys import argv
import traceback

from lib.monitor import Monitor
from lib.queue import Queue, Mutant
from lib.fuzzer import BBFeedbackFuzzer, FuzzerException


__version__ = "0.15"


class TargetStateException(Exception):
	pass


in_dir = argv[1]
out_dir = argv[2]
target_ip = "10.0.0.64"
target_port = 8888
#target_ip = "192.168.27.31"
#target_port = 5413

def post_send(target):
	if not target.recv(1024):
		raise TargetStateException("drop to init state")


queue = Queue(in_dir)
queue.draw()
monitor = Monitor(target_ip, port=31338)
fuzzer = BBFeedbackFuzzer(monitor, workdir=out_dir)

while True:
	try:
		#print "attempt"
		target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		target.connect( (target_ip, target_port) )
		target.settimeout(0.5)
		fuzzer.fuzz( target, queue, post_send_callback=post_send )
	except KeyboardInterrupt:
		traceback.print_exc()
		target.close()
		break
	except (socket.error, socket.timeout, TargetStateException, FuzzerException) as e:
		#[Errno 111] Connection refused
		#print str(e)
		target.close()
	except Exception as e:
		traceback.print_exc()


