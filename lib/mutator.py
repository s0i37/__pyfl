import socket
from subprocess import Popen, PIPE

__version__ = '0.10'

class Radamsa:
	def __init__(self, radamsa="/opt/radamsa/bin/radamsa"):
		self.radamsa_bin = radamsa
		self.radamsa_port = 51337
		self.proc = None

	def __call__(self, pattern, count, test_case=1):
		if self.proc and self.proc.poll() == None:
			self.proc.kill()
			self.proc.terminate()

		if not self.proc or self.proc.poll() != None:
			self.pattern = pattern
			cmd = "{bin} -m bf -o :{port} -n {count} --seek {test_case} -M - -".format(bin=self.radamsa_bin, port=self.radamsa_port, count=count, test_case=test_case)
			self.proc = Popen( cmd.split(), stdin=PIPE, stdout=PIPE )
			self.proc.stdin.write(self.pattern)
			self.proc.stdin.close()

		return self

	def __iter__(self):
		while self.proc.poll() == None:
			try:
				s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
				s.connect( ('127.0.0.1', self.radamsa_port) )
				data = s.recv(4096)
				yield data
				s.close()
		#		stdout.write( self.out() + "\r" )
		#		stdout.flush()
			except Exception as e:
				pass
		#print ""

	def out(self):
		line = self.proc.stdout.readline()
		output = []
		for info in line.split(','):
			is_interesting_output = True
			for non_interesting_output in ["generator:", "checksum:", "ip:", "port:", "output:"]:
				if info.find(non_interesting_output) != -1:
					is_interesting_output = False
					break
			if is_interesting_output:
				output.append(info)
		output = ','.join(output).replace("\n", " ")
		if len(output) >= 60:
			return output[:60] + '...'
		else:
			return output
