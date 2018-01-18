from os import path
from sys import stdout
from colorama import Fore
from json import dumps
from random import random
from time import time, sleep

from lib.queue import Sample

__version__ = '0.13'

def delta_cov(_input):
	coverage = {}
	delta = {}
	if _input.prev_coverage:
		for bb,exec_count in _input.prev_coverage.items():
			coverage[int(bb)] = exec_count
		for bb,exec_count in _input.coverage.items():
			if not int(bb) in coverage.keys():
				delta[int(bb)] = exec_count
			elif coverage.get(int(bb)) != exec_count:
				delta[int(bb)] = exec_count
	return delta

class FuzzerException(Exception):
	pass

class FeedbackFuzzer():
	def __init__(self, monitor, workdir):
		self.monitor = monitor
		self.workdir = workdir
		self.know_coverages = []
		self.know_basic_blocks = []
		self.is_new_coverage = False
		self.interval = 0.5
		self.hang_time = 10

	def log_coverages(self, info):
		if not 'coverages_log' in dir(self):
			self.coverages_log = open( path.join(self.workdir, "coverages.jl"), "w" )
		self.coverages_log.write(info)
		self.coverages_log.flush()

	def log_basic_blocks(self, info):
		if not 'basic_blocks_log' in dir(self):
			self.basic_blocks_log = open( path.join(self.workdir, "basic_blocks.jl"), "w" )
		self.basic_blocks_log.write(info)
		self.basic_blocks_log.flush()

	def save_interesting_input(self, mutant):
		with open( path.join(self.workdir, "%s.bin" % mutant.id), "wb") as o:
			o.write( str(mutant) )

	def save_hang(self, mutant):
		with open( path.join(self.workdir, "hang_%s.bin" % mutant.id), "wb") as o:
			o.write( str(mutant) )

	def save_exception(self, mutant):
		with open( path.join(self.workdir, "exception_%s.bin" % mutant.id), "wb") as o:
			o.write( str(mutant) )

	def wait(self):
		if self.interval:
			sleep(self.interval)

	def __del__(self):
		if 'coverages_log' in dir(self):
			self.coverages_log.close()
		if 'basic_blocks_log' in dir(self):
			self.basic_blocks_log.close()



class BBFeedbackFuzzer(FeedbackFuzzer):
	def __init__(self, monitor, workdir):
		FeedbackFuzzer.__init__(self, monitor, workdir)
		self.new_inputs = []
		self.is_new_coverage = False

	def fuzz(self, target, queue, pre_send_callback=lambda target:True, post_send_callback=lambda target:True):
		self.has_new_input = False
		exception = None

		if not self.new_inputs:
			self.gen_inputs(queue)
			if len(self.new_inputs) >= 2 and str(self.new_inputs[0]).startswith('q') and str(self.new_inputs[1]).startswith('w'):
				print Fore.RED + str( map(str, self.new_inputs) ) + Fore.RESET
				import pdb; pdb.set_trace()


		try:
			self.send(target, self.new_inputs, pre_send_callback, post_send_callback)
		except Exception as e:
			exception = e
		print "x"

		self.is_new_coverage = self.has_new_coverage(self.new_inputs)
		
		self.save(self.new_inputs)

		if self.is_new_coverage and self.interval <= self.hang_time:
			#for new_input in self.new_inputs:
			#	delta = delta_cov(new_input)
			#	if delta:
			#		print "%s: %s" % ( str(new_input.id), str(delta) )
			print "(+)",
			if self.interval < 0.05:
				self.interval += 0.05
			else:
				self.interval += self.interval/5
		else:
			print "(-)",
			self.new_inputs = []
			self.interval -= self.interval/5

		if self.has_new_input:
			queue.draw()
		
		if exception:
			raise exception

	def gen_inputs(self, queue):
		#print "gen_inputs"
		if len(queue):
			'''
			Firstly.
			Send samples and move to down on samples tree. We dont save interesting input - because it is samples.
			The main purpose of this - it is collect of coverages.
			'''
			for _input in queue:
				if isinstance(_input, Sample) and not _input.was_send:
					#print 'probe sample ',
					_input.top_level_queue = queue
					_input.top_level_input = None
					self.new_inputs.append( _input )
					self.gen_inputs(_input.queue)
			'''
			Next.
			We get a something input of current level.
			'''
			current_input = queue.min_fuzzed_input()
			'''
			If it is a not the deepest level and with something probability - 
			we send originaly input so that go to down on inputs tree.
			'''
			if len( current_input.queue ) and random() > 0.5:
				''' in the deep '''
				#print "in the deep ",
				current_input.top_level_queue = queue
				current_input.top_level_input = current_input
				self.new_inputs.append( current_input )
				self.gen_inputs(current_input.queue)
			else:
				''' in the width '''
				for mutant in current_input:
					#print 'in the width'
					mutant.top_level_queue = queue
					mutant.top_level_input = current_input
					self.new_inputs.append( mutant )
					break

	def send(self, target, inputs, pre_send_callback=lambda target:True, post_send_callback=lambda target:True):
		for this_input in inputs:
			print this_input.id + " -> ",

			pre_send_callback(target)
			if this_input.coverage:
				this_input.prev_coverage = this_input.coverage
			begin_time = time()

			self.monitor.reset_coverage()
			self.wait()
			target.send( str(this_input) )
			self.wait()
			this_input.coverage = self.monitor.get_coverage()

			this_input.timeout = time() - begin_time
			this_input.state = self.monitor.get_state()
			this_input.was_send = True
			post_send_callback(target)

	def has_new_coverage(self, inputs):
		for this_input in inputs:
			if this_input.coverage:
				if not this_input.prev_coverage and not this_input.coverage in self.know_coverages:
					return True
				elif this_input.prev_coverage and this_input.coverage != this_input.prev_coverage:
					return True
		return False

	def save(self, inputs):
		for this_input in inputs:
			if this_input.state and this_input.state["is_exception"]:
				print Fore.RED + "[!] exception detected" + Fore.RESET
				self.save_exception(this_input)

			if this_input.timeout > self.hang_time:
				print Fore.LIGHTYELLOW_EX + "[!] hang detected" + Fore.RESET
				self.save_hang(this_input)
			
			new_bb = []
			if this_input.coverage:
				new_bb = set( this_input.coverage.keys() ) - set(self.know_basic_blocks)
				if new_bb:
					print Fore.GREEN + "[+] new basic blocks: %s" % ','.join( map( lambda bb:"%s(%s)"%(bb,this_input.coverage[bb]), new_bb ) ) + Fore.RESET
					#self.log_basic_blocks( "%s: %s\n" % ( this_input.id, dumps(self.monitor.new_bb) ) )

			if this_input.coverage and not this_input.coverage in self.know_coverages \
			and this_input.prev_coverage and this_input.coverage == this_input.prev_coverage and new_bb:
				print "save coverage"
				self.know_coverages.append( this_input.coverage )
				self.know_basic_blocks.extend( new_bb )
				if not str(this_input) in map(str, this_input.top_level_queue)\
				and not isinstance(this_input, Sample):
					this_input.make_name( "%s(from %s)" % ( repr(this_input)[:50], this_input.top_level_input.name ) )
					this_input.top_level_queue << this_input
					this_input.queue << this_input.top_level_input.queue
					self.save_interesting_input( this_input )
					print Fore.LIGHTGREEN_EX + ( "[+] new path found in (%s) [%s]" % ( repr(this_input), this_input.id ) ) + Fore.RESET
					self.has_new_input = True
				self.log_coverages( "%s: %s\n" % ( this_input.id, dumps(this_input.coverage) ) )