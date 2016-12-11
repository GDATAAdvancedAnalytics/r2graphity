from hashlib import sha1, md5
from os.path import basename, getsize
import magic
import pydeep
import pefile
import time
import math


# receives a string, containing a symbol a la radare2
# returns the sole API name

def gimmeDatApiName(wholeString):
	# TODO do something smarter here one day.. 
	if '.dll_' in wholeString:
		apiName = wholeString.split('.dll_')[1].replace(']','')
		return apiName
	elif '.DLL_' in wholeString:
		apiName = wholeString.split('.DLL_')[1].replace(']','')
		return apiName
	elif '.SYS_' in wholeString:
		apiName = wholeString.split('.SYS_')[1].replace(']','')
		return apiName
	elif '.exe_' in wholeString:
		apiName = wholeString.split('.exe_')[1].replace(']','')
		return apiName
	elif 'sym._' in wholeString:
		apiName = wholeString.split('sym._')[1].replace(']','')
		return apiName
	else:
		print "DAT API STRING was malformed or something, pls check %s" % wholeString
		return wholeString

# checks whether a string is pure ascii

def is_ascii(myString):
	try:
		myString.decode('ascii')
		return True
	except UnicodeDecodeError:
		return False

# SAMPLE ATTRIBUTE GETTERS

 # MD5
 # filename
 # filetype
 # ssdeep
 # imphash
 # size
 # compilationTS
 # address of EP
 # EP section
 # number of section
 # original filename
 # number TLS sections
 
def sha1hash(path):
	content = file(path, 'rb').read()
	return sha1(content).hexdigest()
	
def md5hash(path):
	content = file(path, 'rb').read()
	return md5(content).hexdigest()
	
def getFilename(path):
	return basename(path)

def getFiletype(path):
	return magic.from_file(path)

def getFilesize(path):
	return getsize(path)
	
def getPeSubsystem(path):
	pass

def getSsdeep(path):
	return pydeep.hash_file(path)
	
def getImphash(pe):
	return pe.get_imphash()

def getCompilationTS(pe):	
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp))

def getEPAddress(pe):
	return pe.OPTIONAL_HEADER.AddressOfEntryPoint
	
def getSectionCount(pe):
	return pe.FILE_HEADER.NumberOfSections
	
def getOriginalFilename(pe):
	oriFilename = ""
	if hasattr(pe, 'VS_VERSIONINFO'):
		if hasattr(pe, 'FileInfo'):
			for entry in pe.FileInfo:
				if hasattr(entry, 'StringTable'):
					for st_entry in entry.StringTable:
						for str_entry in st_entry.entries.items():
							if 'OriginalFilename' in str_entry:
								# UGLY DIRTY TRICK to sanitize values
								try:
									oriFilename = str(str_entry[1].decode("ascii", "ignore"))
								except:
									oriFilename = "PARSINGERR"
	return oriFilename

def getEPSection(pe):
	name = ''
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	pos = 0
	for sec in pe.sections:
		if (ep >= sec.VirtualAddress) and \
		   (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
			name = sec.Name.replace('\x00', '')
			name = name.decode("ascii", "ignore")
			break
		else:
			pos += 1
	return (name + "|" + pos.__str__())

def getTLSSectionCount(pe):
	idx = 0
	if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and
	   pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

		while True:
			func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
			if func == 0:
				break
			idx += 1
	return idx
	
# Returns Entropy value for given data chunk
def Hvalue(data):
	if not data:
		return 0

	entropy = 0#
	for x in range(256):
		p_x = float(data.count(chr(x))) / len(data)
		if p_x > 0:
			entropy += - p_x * math.log(p_x, 2)

	return entropy
	

def getCodeSectionSize(pe):

	for section in pe.sections:
		print section		

def getSectionInfo(pe):

	# Section info: names, sizes, entropy vals
	sects = []
	vadd = []
	ent = []
	secnumber = getSectionCount(pe)

	for i in range(12):

		if (i + 1 > secnumber):
			strip = ""
			strap = ""
			entropy = ""

		else:
			stuff = pe.sections[i]
			strip = stuff.Name.replace('\x00', '')
			strap = str(stuff.SizeOfRawData).replace('\x00', '')

			entropy = Hvalue(stuff.get_data())

		section_name = ""
		try:
			section_name = strip.decode("ascii", "ignore")
		except:
			section_name = "PARSINGERR"

		sects.append(section_name)
		ent.append(entropy)
		if strap.isdigit():
			vadd.append(int(strap))
		else:
			vadd.append('')

	secinfo = sects + vadd + ent
	return secinfo
	
	
	
def getAllAttributes(path):
	
	allAtts = {}
	
	allAtts['md5'] = md5hash(path)
	allAtts['sha1'] = sha1hash(path)
	allAtts['filename'] = getFilename(path)
	allAtts['filetype'] = getFiletype(path)
	allAtts['ssdeep'] = getSsdeep(path)
	allAtts['filesize'] = getFilesize(path)
	
	try:
		pe = pefile.PE(path)
		if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
			allAtts['imphash'] = getImphash(pe)
			allAtts['compilationts'] = getCompilationTS(pe)
			allAtts['addressep'] = getEPAddress(pe)
			allAtts['sectionep'] = getEPSection(pe)
			allAtts['sectioncount'] = getSectionCount(pe)
			allAtts['sectioninfo'] = getSectionInfo(pe)
			allAtts['tlssections'] = getTLSSectionCount(pe)
			allAtts['originalfilename'] = getOriginalFilename(pe)
	
	except (pefile.PEFormatError):
		pass
	
	return allAtts
