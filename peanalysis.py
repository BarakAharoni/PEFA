from msilib import _directories
import pefile
import peutils
import subprocess as subp
import ctypes
import os
import hashlib
from datetime import datetime

# Magic header
# Is executable
# IAT
# EAT
# Import table hash
# SHA1, SHA256, MD5
# File protections - ASLR, DEP, SEH, FI, CFG
# Timestamp
# File headers
# Strings
# Digital sig
# File size
# Entry point
# Resources
#

# Constants
#                     'MZ'   , 'PE' - little endian
FORMATS = {'exe' : ['0x5a4d' , '0x4550'] , 'pdf' : ['','']}
FIRST_BYTES = 4
PE_MAGIC = b'MZ\x90\x00'
BINARY_32BIT = '0x14c' # 0x8664 = x86-x64 binary

class PEAnalysis:
    def __init__(self, path):
        try:
            self.pe = pefile.PE(path)
        except:
            self.pe = None
        self.data = open(path, 'rb').read()
        self.magic = self.getMagicHeader()
        self.path = path
        self.size = self.getFileSize()
        self.version = self.checkBinaryVersion()
        self.timestamp = self.getTimeStamp()
        self.exec = self.isExecutable()
        self.hashes = {"SHA1" : self.getSHA1(), "SHA256" : self.getSHA256(), "MD5" : self.getMD5()}
        self.headers = self.getHeaders()
        self.digitalSig = self.getDigitalSignature()
        self.entryPoint = self.getEntryPoint()
        self.imageBase = self.getImageBase()
        self.imports = self.getIAT()
        self.exports = self.getEAT()
        self.resources = self.getResources()
        self.imphash = self.getImpHash()
        self.protections = {"ASLR" : self.getASLR(), "Data Execution Prevention (DEP)" : self.getDEP(), "SEH" : self.getSEH(), "Force Integrity" : self.getFI(), "Control Flow Guard (CFG)" : self.getCFG()}
        self.hidden = self.isHidden()
        self.sus = self.isSuspicious()

    def getMagicHeader(self):
        return (hex(self.pe.DOS_HEADER.e_magic)).split("x")[1]#.decode("hex") #[:1]

    def getMachine(self):
        return hex(self.pe.FILE_HEADER.Machine)

    def getFileSize(self):
        size = os.path.getsize(self.path)
        if size < 1024:
            size = str(size) + 'Bytes'
        elif size / 1024 < 1024:
            size = str(size / 1024.0)[:4] + "KB"
        elif size / (1024 ** 2) < 1024:
            size = str(size / (1024.0 ** 2))[:4] + "MB"
        else:
            size = str(size / (1024.0 ** 3))[:4] + "GB"

        return size

    def checkBinaryVersion(self):
        
        # Check if it is a 32-bit or 64-bit binary
        if hex(self.pe.FILE_HEADER.Machine) == BINARY_32BIT:
            return ("This is a 32-bit binary")
        return ("\tThis is a 64-bit binary")

    # Get file timestamp
    # Return Timestamp format 
    def getTimeStamp(self):
        return(self.pe.FILE_HEADER.TimeDateStamp)#.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])

    def isExecutable(self):
        with open(self.path, 'rb') as f:
                header = f.read()[:FIRST_BYTES]
        if header == PE_MAGIC:
            return True
        return False

    def getSHA1(self):
        sha1 = hashlib.sha1(self.data)
        return sha1.hexdigest()

    def getSHA256(self):
        sha256 = hashlib.sha256(self.data)
        return sha256.hexdigest()

    def getMD5(self):
        md5 = hashlib.md5(self.data)
        return md5.hexdigest()

    def getHeaders(self):
        nt_header = (hex(self.pe.NT_HEADERS.Signature)).split("x")[1]#.decode("hex")
        return nt_header

    def getDigitalSignature(self):
        pass

    def getEntryPoint(self):
        return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def getImageBase(self):
        return self.pe.OPTIONAL_HEADER.ImageBase

    def getIAT(self):

        # {Module: {Func : Address}} dictionary
        iat = {}
        self.pe.parse_data_directories(directories=[1])
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            funcList = {}

            for imp in entry.imports:
                funcList[imp.name.decode('utf-8')] = hex(imp.address)
                iat[entry.dll.decode('utf-8')] = funcList
        return iat

    def getEAT(self):
        exports = {}
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports[exp.name.decode('utf-8')] = hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)
        except:
            pass
        return exports

    def getResources(self):
        pass
        """
        resourceDict = {}
        dirNum = 0
        if self.pe:
            for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                entryNum = 0
                dirName = rsrc.name.__str__()
                if rsrc.name.__str__() == 'None':
                    dirName = "Unnamed_Dir_" + str(dirNum)
                    dirNum += 1
                resourceDict[dirName] = []

                for entry in rsrc.directory.entries():
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
            
                    rsrcData = self.pe.get_memory_mapped_image()[offset:offset+size]
        """


    def getImpHash(self):
        return self.pe.get_imphash()

    def getASLR(self):
        return self.pe.NT_HEADERS.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    def getDEP(self):
        return self.pe.NT_HEADERS.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT

    def getSEH(self):
        return (not self.pe.NT_HEADERS.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH)

    def getFI(self):
        return (self.pe.NT_HEADERS.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)

    def getCFG(self):
        return (self.pe.NT_HEADERS.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    # Checks if the file is hidden or not 
    # return true if file is hidden
    def isHidden(self):
        name = os.path.basename(os.path.abspath(self.path))
        return(name.startswith('.') or self.hasHiddenAttribute())

    def hasHiddenAttribute(self):
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(self.path)
            assert attrs != -1
            result = bool(attrs & 2)
        except (AttributeError, AssertionError):
            result = False
        return result

    # Unusual locations of import tables, Non recognised section names, Presence of long ASCII strings
    def isSuspicious(self):
        return peutils.is_suspicious(self.pe)

    def checkFileFormat(self):

        file_format = self.path.split('.')[1]
        print("Analyze file: {}".format(self.path))

        # Check if MZ in file header
        if hex(self.pe.DOS_HEADER.e_magic) == FORMATS[file_format][0]:
            print('\te_magic = MZ Header')
        else:
            print('\tNOT EXE File')
            
        # Check if PE in signature
        if hex(self.pe.NT_HEADERS.Signature) == FORMATS[file_format][1]:
            print("\tSignature= PE")
        else:
            print("\tSignature= NO PE")

    # Print Hashes of the file in readable format
    def printFileHash(self):
        finalStr = "\n\t"
        for hash, value in self.hashes.items():
            finalStr += "\t [-] {}: {}\n\t".format(hash, value)
        return finalStr

    def printIAT(self):
        iat = ""
        for dll in self.imports.keys():
            iat += "\n\t\t[+] {}".format(dll)
            for func in self.imports[dll].keys():
                iat += '\n\t\t\t[-] {:>10}\t{}'.format(self.imports[dll][func], func)
        return iat

    def printEAT(self):
        eat = ""
        for exp in self.exports.keys():
            address = self.exports[exp]
            eat += '\n\t\t{:>10} {}'.format(self.exports[exp], exp)
        return eat

    def printDict(self, dict):
        output = "\n\t"
        for key,val in dict.items():
            if(val):
                output += "\t[V] {}\n\t".format(key, val)
            else:
                output += "\t[X] {}\n\t".format(key, val)
        return output

    def printSecionsEntropy(self):
        print("\tSections and Entropy")
        for sect in self.pe.sections:
            print("\t\t{:<10}{}".format(sect.Name.decode('utf-8'), sect.get_entropy()))

    # Create full reporst of PE Analysis
    def createReport(self, outputPath):
        if outputPath != "":
            print("Create Report at: {}".format(outputPath))
        else:
            print("PE Analyzed: {}".format(self.path))
            print("\t{}".format(self.checkBinaryVersion()))
            print("\tMagic (DOS Heaer): {} ({}{})".format(self.magic, bytes.fromhex(self.magic[2:]).decode("ASCII"), bytes.fromhex(self.magic[:2]).decode("ASCII")))
            print("\tFile Size: {}".format(self.size))
            print("\tTimeStamp: {}".format((datetime.utcfromtimestamp(int(self.timestamp)).strftime('%d-%m-%Y %H:%M:%S'))))
            print("\tIs Executable: {}".format(self.exec))
            print("\tFile Hashes: {}".format(self.printFileHash()))    
            print("\tFile Headers (NT Header): {} ({}{})".format(self.headers, bytes.fromhex(self.headers[2:]).decode("ASCII"), bytes.fromhex(self.headers[:2]).decode("ASCII")))            
            print("\tDigital Signature: {}".format(self.digitalSig))                ##
            print("\tEntryPoint: {}".format(hex(self.entryPoint)))
            print("\tImageBase: {}".format(hex(self.imageBase)))
            self.printSecionsEntropy()
            print("\tImport Table: {}".format(self.printIAT()))
            print("\tExport Table: {}".format(self.printEAT()))
            print("\tResources: {}".format(self.resources))                         ##
            print("\tImport Hash: {}".format(self.imphash))
            print("\tFile Protections: {}".format(self.printDict(self.protections)))
            print("\tIs Hidden: {}".format(self.hidden))
            print("\tIs Suspicous: {}".format(self.sus))

    ##################################################################
    #                       Advanced Analysis                       #
    ##################################################################
    
    # Get memory mapped image for Disassemble feature
    def getMemoryMappedImage(self):
        return self.pe.get_memory_mapped_image()