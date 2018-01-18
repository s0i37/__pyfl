from os import listdir, path
import pydot
from mutator import Radamsa
import string

__version__ = '0.11'

radamsa = Radamsa()

class Input:
	def __init__(self, data):
		self.data = data
		self.coverage = None
		self.prev_coverage = None
		self.state = {}
		self.timeout = None

	def __str__(self):
		return self.data

	def __len__(self):
		return len(self.data)

	def __repr__(self):
		out = ''
		for ch in str(self):
			if ch in string.ascii_letters + string.digits + string.punctuation:
				out += ch
			else:
				out += "%02X" % ord(ch)
		return out

	def make_name(self, name):
		self.name = name


class Sample(Input):
	def __init__(self, data):
		Input.__init__(self, data)
		self.id = None
		self.name = 'new_sample'
		self.mutants = {}
		self.fuzz_offset = 1
		self.queue = Queue()
		self.was_send = False

	def __iter__(self):
		while True:
			if not self.mutants.keys() or max( self.mutants.keys() ) < self.fuzz_offset:
				self.mutants = {}
				i = self.fuzz_offset
				for data in radamsa( self.data, count=100, test_case=self.fuzz_offset ):
					new_mutant = Mutant(data)
					new_mutant.id = "%s-%d" % (self.id, i)
					self.mutants[i] = new_mutant
					i += 1
			self.fuzz_offset += 1
			yield self.mutants[ self.fuzz_offset - 1 ]

	def copy(self):
		return Sample( str(self) )


class Mutant(Input):
	def __init__(self, data):
		Input.__init__(self, data)
		self.id = None
		self.name = 'new_mutant'
		self.mutants = {}
		self.fuzz_offset = 1
		self.queue = Queue()

	def __iter__(self):
		while True:
			if not self.mutants.keys() or max( self.mutants.keys() ) < self.fuzz_offset:
				self.mutants = {}
				i = self.fuzz_offset
				for data in radamsa( self.data, count=100, test_case=self.fuzz_offset ):
					new_mutant = Mutant(data)
					new_mutant.id = "%s-%d" % (self.id, i)
					self.mutants[i] = new_mutant
					i += 1
			self.fuzz_offset += 1
			yield self.mutants[ self.fuzz_offset - 1 ]


class Queue:
	def __init__(self, directory=''):
		self.id = "0"
		self.level = 0
		self.inputs = []
		if directory:
			self.scan_dir(directory, self)

	def __str__(self):
		return str( self.inputs )

	def scan_dir(self, dirname, queue):
		for filename in listdir(dirname):
			filepath = path.join(dirname, filename)
			if path.isfile(filepath):
				with open(filepath, 'rb') as f:
					sample = Sample( f.read() )
				sample.make_name( "(%s)" % filepath )
				queue << sample								# in the width
		
		for filename in listdir(dirname):
			filepath = path.join(dirname, filename)
			if path.isdir(filepath):
				for _input in queue:
					self.scan_dir(filepath, _input.queue)	# in the depth

	def __len__(self):
		return len( self.inputs )

	def max_fuzzed_input(self):
		fuzz_count_max = 0
		input_max = None
		for _input in self.inputs:
			if fuzz_count_max <= _input.fuzz_offset:
				fuzz_count_max = _input.fuzz_offset
				input_max = _input
		return input_max

	def min_fuzzed_input(self):
		fuzz_count_min = 0xffffff
		input_min = None
		for _input in self.inputs:
			if fuzz_count_min >= _input.fuzz_offset:
				fuzz_count_min = _input.fuzz_offset
				input_min = _input
		return input_min

	def __iter__(self):
		return iter(self.inputs)

	def __getitem__(self, item):
		if isinstance(item, int):
			return self.inputs[item]

	def __lshift__(self, obj):
		if isinstance( obj, (Sample, Mutant) ):
			new_input = obj
			new_input.queue.id = '%s-%d' % ( self.id, len(self.inputs) + 1 )
			new_input.queue.level = self.level + 1
			new_input.id = new_input.queue.id[2:]
			self.inputs.append(new_input)
		elif isinstance(obj, Queue):
			queue = obj
			def walk(queue_write, queue_read):
				if(queue_write.id != queue_read.id):
					for input_read in queue_read:
						if isinstance(input_read, Sample):
							sample = input_read.copy()
							sample.name = input_read.name
							queue_write << sample
					for i in xrange( len(queue_write) ):
						queue_write[i].queue << queue_read[i].queue
			
			walk(queue_write=self, queue_read=queue)
		return self

	def draw(self, filename="out/inputs.png"):
		graph = pydot.Dot(graph_type='graph')
		def walk_on_queue(input_parent, queue, graph):
			for _input in queue:
				node_name = _input.name
				#node_name = _input.id
				if isinstance(_input, Mutant):
					graph.add_node( pydot.Node( node_name, style="filled", fillcolor='green', fontcolor='black' ) )
				elif isinstance(_input, Sample):
					graph.add_node( pydot.Node( node_name, style="filled", fillcolor='white', fontcolor='black' ) )
				graph.add_edge( pydot.Edge( input_parent, node_name ) )
				if len( _input.queue ):
					walk_on_queue( node_name, _input.queue, graph )

		walk_on_queue('init_state', self, graph)
		graph.write_png(filename)
