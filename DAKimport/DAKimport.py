#!/usr/bin/python3

import sys
import numpy as np
from collections import Counter
from PIL import Image
from .stp import read_stp
# import png


def signExt_b2d(x):
	return (((x & 0xFF) ^ 0x80) - 0x80) & 0xFFFFFFFF

def getByteAt(data, i):
	return data[i] & 0xFF

def getWordAt(data, i):
	return getByteAt(data, i) + (getByteAt(data, i + 1) << 8)

def getDWordAt(data, i):
	return getWordAt(data, i) + (getWordAt(data, i + 2) << 16)

## Pascal-style string
def getStringAt(data, i):
	size = getByteAt(data, i)
	return data[i + 1:i + size + 1].decode()


class DAKColor:

	def __init__(self, code = 0x10, n = None, symbol = "", name = "",
		r = np.uint8(), g = np.uint8(), b = np.uint8(), binary = None):
		if binary != None:
			self.code = getByteAt(binary, 0)
			self.n = getByteAt(binary, 3)
			self.symbol = getByteAt(binary, 1)
			self.name = getStringAt(binary, 9)
			self.rgb = bytearray([getByteAt(binary, 6), getByteAt(binary, 7), getByteAt(binary, 8)])
		else:
			self.code = code
			self.n = n
			self.symbol = symbol
			self.name = name
			self.rgb = bytearray([r, g, b])

	def string(self):
		return ("{0}, {1}, '{2}', '{3}', {4}") \
		.format(hex(self.code), str(self.n), chr(self.symbol), self.name,
			hex(int.from_bytes(self.rgb, 'big')))

## end of DAKColor class definition


class DAKStitch:

	def __init__(self, i, j, k, a, b, c, d, e):
		self.i = i
		self.j = j
		self.k = k
		self.a = a
		self.b = b
		self.c = c
		self.d = d
		self.e = e

	def string(self):
		return ("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}") \
		.format(hex(self.i), hex(self.j), hex(self.k), hex(self.a), hex(self.b),
			hex(self.c), hex(self.d), hex(self.e))

## end of DAKStitch class definition


class STPBlock:

	def __init__(self, buffer, start, xorkey = None):
		self.height = getWordAt(buffer, start)
		self.size = getWordAt(buffer, start + 2)
		if xorkey != None:
			self.data = bytearray(self.size)
			for i in range(self.size):
				self.data[i] = buffer[start + 4 + i] ^ xorkey[i]
		else:
			self.data = buffer[start + 4:start + 4 + self.size]

## end of STPBlock class definition


class DAKPatternConverter:

	def __init__(self, debug = True):
		self.filename = None
		self.height = None
		self.width = None
		self.color_pattern = bytearray()
		# self.stitch_pattern = bytearray()
		# self.extension = bytearray()
		self.colors = {}
		# self.stitches = {}
		# self.max_row_colors = 0
		# self.col1 = 0
		# self.col2 = 0x3C ## '<'
		# self.status = 0
		self.debug = False

	def __read_data(self, filename):
		self.__init__()
		self.filename = filename
		if self.debug:
			print("filename {}".format(self.filename))
		file = open(self.filename, "rb")
		if file is None:
			self.__exit("file not found", -3)
		data = file.read()
		file.close()
		size = len(data)
		if self.debug:
			print("input size {} bytes".format(hex(size)))
		return data

	def __check_header(self, header, ok_headers):
		if self.debug:
			print("header {}".format(header))
		if header not in ok_headers:
			self.__exit("file header not recognized", -4)

	def __check_dims(self, data, w_pos, h_pos, w_max, h_max):
		self.width = getWordAt(data, w_pos)
		self.height = getWordAt(data, h_pos)
		if self.debug:
			print("width {}".format(self.width))
			print("height {}".format(self.height))
		if self.width > w_max or self.height > h_max:
			self.__exit("dimensions are too big", -2)

	def __find_col1(buffer, start):
		pos = start
		for i in range(0x47):
			if buffer[pos] & 0x50 == 0x50:
				return i
			else:
				pos += 0x19
		return 0x20 ## default value for col1

	## block of color data after pattern block = 1775 bytes = 0x47 * 0x19
	def __read_colors(self, buffer, start):
		pos = start
		for i in range(0x47):
			b = buffer[pos:pos + 0x1A]
			# if b[0] & 0x10 and b[1] > 0: ## works for .pat file
			if b[0] & 0x10: ## works for .stp file
				new_color = DAKColor(binary = b)
				# self.colors[b[1]] = new_color ## works for .pat file
				self.colors[i] = new_color ## works for .stp file
				if self.debug:
					print("new_color '{}' {}".format(chr(i), new_color.string()))
			pos += 0x19

	# def __read_stitches(self, data, start):
	# 	pos = start
	# 	for i in range(0x30):
	# 		k = data[pos + 1]
	# 		if k != 0:
	# 			j = data[pos]
	# 			x = (data[4 * j + 3] & 0xF) | ((k & 5) << 4)
	# 			new_stitch = DAKStitch(i + 1, j, k, data[4 * j], data[4 * j + 1], data[4 * j + 2], data[4 * j + 3], x)
	# 			self.stitches[i + 1] = new_stitch
	# 			if self.debug:
	# 				print(f"new_stitch {new_stitch.string()}")
	# 		pos += 2


	# def __output_png(self):
	# 	rgb = [[num for element in [self.colors[self.color_pattern[self.height - row - 1, column]].rgb \
	# 	for column in range(self.width)] for num in element] for row in range(self.height)]
	# 	return png.from_array(rgb, mode = 'RGB')

	def __output_im(self):
		rgb = np.array([[self.colors[self.color_pattern[self.height - row - 1, column]].rgb \
		for column in range(self.width)] for row in range(self.height)],
		np.uint8)
		if self.debug:
			print(rgb, file=sys.stderr)
		return Image.fromarray(rgb, mode = 'RGB')

	def __exit(self, msg, return_code):
		print(msg)
		# self.status = return_code
		# sys.exit(self.status)
		sys.exit(return_code)

	# read DAK .pat file and return a PIL.Image object
	def pat2im(self, filename):
		## constants
		dst_pos = 0x10
		pattern_start = 0x165
		#
		## read data
		input_data = self.__read_data(filename)
		input_size = len(input_data)
		#
		## check data
		self.__check_header(input_data[0:3], (b'D4C', b'D6C'))
		self.__check_dims(input_data, 0x13A, 0x13C, 500, 800)
		# self.status = 0
		#
		## decode run length encoding of color pattern
		## count colors
		self.color_pattern = np.zeros((self.height, self.width,), np.uint8)
		pos = pattern_start
		# all_colors = set()
		for row in range(self.height):
			row_colors = set()
			column = 0
			while column < self.width:
				run = 1
				color = getByteAt(input_data, pos)
				pos += 1
				if color & 0x80:
					run = color & 0x7F
					color = getByteAt(input_data, pos)
					pos += 1
				# all_colors.add(color)
				# row_colors.add(color)
				if run > 0:
					for i in range(run):
						self.color_pattern[row, column] = color
						column += 1
			# self.max_row_colors = max(self.max_row_colors, len(row_colors))
		#
		## no stitch data
		# self.stitch_pattern = np.zeros((self.height, self.width), np.uint8)
		#
		## get base color
		# b151 = getByteAt(input_data, 0x151)
		# if b151:
		# 	self.col1 = np.int8(b151) + 0x100
		# else:
		# 	self.col1 = 0
		# self.col2 = getByteAt(input_data, 0x152)
		#
		## calculate return code
		# b15A = getByteAt(input_data, 0x15A)
		# if b15A == 0x0E or b15A == 0x0F:
		# 	self.status = 0
		# else:
		# 	self.status = b15A
		# if self.status == 0 or \
		# self.status < self.max_row_colors or \
		# self.max_row_colors > 2:
		# 	self.status = self.max_row_colors
		#
		## go to end of pattern block
		pos += 1
		while pos < input_size:
			pos += 1
			if getByteAt(input_data, pos - 1) == 0xFE:
				break
			pos += getByteAt(input_data, pos) + 1
			pos += getByteAt(input_data, pos) + 3
		if self.debug:
			print("pos {}".format(hex(pos)))
		#
		## get color information
		## block of color data after pattern block = 1775 bytes = 0x47 * 0x19
		if pos < input_size:
			# if self.col1 == 0:
				# self.col1 = find_col1(input_data, pos)
			self.__read_colors(input_data, pos)
			#
			## get additional information, 6 bytes per row
			## I don't know what these data represent
			# pos += 1775
			# if pos < input_size - 6 and \
			# bytes(input_data[pos:pos + 6]) != b'Arial' and \
			# input_data[pos:pos + 6] != bytearray(6):
			# 	extension = 6 * self.height
			# 	self.extension = input_data[pos:pos + extension]
		#
		## color information before pattern block
		if pos == input_size or len(self.colors) == 0:
			# if self.col1 == 0:
				# self.col1 = Counter(color_array).most_common(1)[0][0]
			color = 0
			for i in range(0x80):
				a = getByteAt(input_data, i + 3)
				if a != 0xFF:
					color += 1
					pos = 3 * (a & 0xF)
					# b = 3 * (self.getByteAt(i + 0x84) & 0xF)
					new_color = DAKColor(
						0x10 + 0x40 * ((self.col1 & 0xFF) == i),
						color,
						chr(i),
						"",
						getByteAt(input_data, 0x107 + pos),
						getByteAt(input_data, 0x106 + pos),
						getByteAt(input_data, 0x105 + pos))
					self.colors[i] = new_color
					if self.debug:
						print("new_color {}".format(new_color.string()))
		# if self.debug:
			# print(f"col1 {hex(self.col1)}")
		#
		## no information on stitch types
		## done
		# return self.status
		return self.__output_im()

	# read DAK .stp file and return a PIL.Image object
	#
	# Decoding is done by DAKimport.stp (see docs/STP_FORMAT.md), which also
	# exposes stitch types, cables, stitch definitions and row yarn data.
	# Raises DAKimport.stp.STPError for invalid files.
	def stp2im(self, filename):
		pattern = read_stp(filename)
		self.__init__()
		self.filename = filename
		self.width = pattern.width
		self.height = pattern.height
		self.color_pattern = np.array([list(row) for row in pattern.color_pattern],
			np.uint8)
		for color in pattern.colors:
			if color.flags & 0x10:
				self.colors[color.index] = DAKColor(binary = color.raw)
		if self.debug:
			print("width {} height {}".format(self.width, self.height))
		return pattern.color_image()

# end of DAKPatternConverter class definition
