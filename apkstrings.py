import string
import zipfile
import binascii
import time
import logging


logger = logging.getLogger("apkstrings")

class APKParseException(Exception):
	pass

def get_binary_strings(f, min=7):
	result = ""
	for c in f.read():
		c = chr(c)
		if c not in "\n\r" and c in string.printable:
			result += c
			continue
		if len(result) >= min:
			yield result
		result = ""
	if len(result) >= min:  # catch result at EOF
		yield result

def _get_dex_strings_count(f):
	f.seek(0x38)
	strings_id = f.read(4)
	a = bytearray(strings_id)
	a.reverse()
	strings_id = bytes(a)
	strings_id = str(binascii.b2a_hex(strings_id), encoding='UTF-8')
	count = int(strings_id, 16)
	return count

def _get_dex_string_bytearr(f, addr):
	bytearr = bytearray()
	f.seek(addr + 1)
	b = f.read(1)
	b = str(binascii.b2a_hex(b), encoding='UTF-8')
	b = int(b, 16)
	index = 2
	while b != 0:
		bytearr.append(b)
		f.seek(addr + index)
		b = f.read(1)
		b = str(binascii.b2a_hex(b), encoding='UTF-8')
		b = int(b, 16)
		index += 1
	return bytearr

def _bytes_to_string(bytearr):
	try:
		return str(bytes(bytearr), encoding='UTF-8')
	except:
		pass

def _get_dex_address(addr):
	address = bytearray(addr)
	address.reverse()
	address = bytes(address)
	address = str(binascii.b2a_hex(address), encoding='UTF-8')
	address = int(address, 16)
	return address

def get_dex_strings(f, min=7):
	f.seek(0x3c)
	string_offset = f.read(4)
	offset = _get_dex_address(string_offset)
	f.seek(offset)
	for i in range(_get_dex_strings_count(f)):
		addr = f.read(4)
		address = _get_dex_address(addr)
		bytearr = _get_dex_string_bytearr(f, address)
		result = _bytes_to_string(bytearr)
		if result and len(result) >= min:
			yield result.strip()
		offset += 4
		f.seek(offset)

def get_package_strings(apk_path, analyze_dex=True, analyze_so=False):
	package = zipfile.ZipFile(apk_path, "r")

	if analyze_dex:
		for dex in zipfile.Path(package, '/').iterdir():
			filename = dex.__str__().split('/')[-1]
			if filename.split('.')[-1] != "dex":
				continue
			logger.info(f"Analyzing {dex}...")
			time.sleep(.1)
			with dex.open("rb") as f:
				for string in get_dex_strings(f):
					yield string
		else:
			logger.warning(f'No classes*.dex files found in "{apk_path}".')
			raise APKParseException("No classes*.dex files found. Not a valid .apk.")

	if analyze_so:
		if zipfile.Path(package, 'lib/').exists():
			libraries = {}
			for package_libraries in zipfile.Path(package, 'lib/').iterdir():
				for library in package_libraries.iterdir():
					library_name = library.__str__().split('/')[-1]
					libraries[library_name] = library

			for (filename, library) in libraries.items():
				logger.info(f"Analyzing {library}...")
				time.sleep(.1)
				with library.open("rb") as f:
					for string in get_binary_strings(f):
						yield string
		else:
			logger.info(f'No .so libraries found in "{apk_path}".')
