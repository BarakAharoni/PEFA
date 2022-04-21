from asyncio.windows_events import NULL
import subprocess as subp
import os
from pathlib import Path

import peanalysis
import yara
from capstone import *
import re

# Constants
BANNER = """

################################################################
#                                                              #
#                                                              #
#    ██████╗ ███████╗███████╗ █████╗                           #
#    ██╔══██╗██╔════╝██╔════╝██╔══██╗                          #
#    ██████╔╝█████╗  █████╗  ███████║                          #
#    ██╔═══╝ ██╔══╝  ██╔══╝  ██╔══██║                          #
#    ██║     ███████╗██║     ██║  ██║                          #
#    ╚═╝     ╚══════╝╚═╝     ╚═╝  ╚═╝                          #
#                                                              #
#    PE File Analysis tool                                     #
#                                                              #
#    Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.   #
################################################################

"""
EXIT_SHELL = "exit"
HELP_MENU = """
    Interactive PE File Analysis Shell

    l or load                        Load file for analysis
    i or info                        Show information about PE File
    y or yara                        Find YARA rules that the file is compatible with
    d or dis                         Enter to disassembler mode
    h or help                        Show the help menu
    e or exit                        Exit the program
    so or setoutput                  Set output file for report

    """
DISASM_HELP = """
    Interactive ThisAssembler Shell
    continue    c   Continue disassemble
    lines       l   Set new lines to show
    jump        j   Jump to Address
    help        h   Help menu
    exit        e   Exit Disassembler Shell
"""

YARA_RULES = {}

################### Extra functionality ###################
def buildYara(rulesPath):
    try:
        for obj in os.listdir(rulesPath):
            fullpath = r"{}\{}".format(rulesPath, obj)
            ext = obj.split(".")[1:]
            if os.path.isfile(fullpath) and len(ext) == 1 and (ext[0] == "yar" or ext[0] == "yara"):
                try:
                    YARA_RULES[obj.split(".")[0]] = yara.compile(fullpath)#, include = True)
                except:
                    pass

            # Recursively yara rules build
            if os.path.isdir(fullpath):
                buildYara(fullpath)
    except:
        pass

def checkYara(data):
    yaraSigs = {}
    for pack, rules in YARA_RULES.items():
        result = rules.match(data = data)
        if result:
            yaraSigs[pack] = result
    return yaraSigs

################### End YARA Rules ###################

################### Disassemble ###################
def disassemblePE(pe, filepath):
 
    # Initialize disassembler to 32 bit x86 binary code
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

    print("\n")
    print("#" * 20)
    print("ThisAssembler")
    print("#" * 20)
    print("\n")

    linesToShow = 50 # Default lines to show
    entrypointAddress = pe.entryPoint + pe.imageBase # Get EntryPoint Address
    addr = entrypointAddress
    startAddr = pe.entryPoint
    endAddr = startAddr + linesToShow
    print("Base Address: {}".format(hex(addr)))
    command = ""

    # Infinity shell until user choose to exit
    while(command.lower() != "exit" and command.lower() != "e"):
        command = input("\nThisAssembler# ")
        binary_code = pe.getMemoryMappedImage()[startAddr:endAddr]

        # Continue disassemble
        if command.lower() == "c" or command.lower() == "continue":
            for instruction in disassembler.disasm(binary_code, entrypointAddress):
                print("\t{}\t{}\t{}".format(hex(addr), instruction.mnemonic, instruction.op_str))
                addr += 1

        # Set new lines to show
        elif command.lower() == "lines" or command.lower() == "l":
            linesToShow = int(input("\nEnter new lines to show: "))

        # Jump to specific address
        elif command.lower() == "jump" or command.lower() == "j":
            startAddr = int(input("\nJump to address: "), 16) - pe.imageBase
            endAddr = startAddr + linesToShow
            addr = startAddr + pe.imageBase
            continue
        
        # Get help
        elif command.lower() == "h" or command.lower() == "help":
            print(DISASM_HELP)

        # Promotion
        startAddr = endAddr - 1
        endAddr += linesToShow

################### End Disassemble ###################


def loadFile():
    global filePath
    filePath = input("pefa\\> Load File: ")
    print(Path(filePath))
    analysisFile = ""

    if filePath.endswith('"'):
        filePath = filePath.replace('"',"")

    print("Analyzing PE File format")
    analysisFile = peanalysis.PEAnalysis(filePath)

    return analysisFile


################### Help Menu ###################
def startShell():
    analysisFile = NULL # Object to analysis based on file format
    command = input("pefa\\> ")
    # Options: info, yara (find, generate), disable (aslr, dep), dis, save, exit
    while command.lower() != EXIT_SHELL and command.lower() != "e":

        if command.lower() == "load" or command.lower() == "l":
            analysisFile = loadFile()

        elif command.lower() == "info" or command.lower() == "i":
            print("info")
            analysisFile.createReport("")
            
        elif command.lower() == "yara" or command.lower() == "y":
            print("[+] Yara Rules checking")
            sigPath = input("\tEnter YARA signatures path: ")
            buildYara(sigPath)

            try:
                yaraSig = checkYara(analysisFile.data)
                for sig in yaraSig.keys():
                    print("\t[+] {}".format(sig))
                    for yar in yaraSig[sig]:
                        print("\t\t[-] {}".format(yar))
            except:
                print("\t[-] Unable to get Yara signatures")

        elif command.lower() == "dis" or command.lower() == "d":
            disassemblePE(analysisFile, analysisFile.path)

        elif command.lower() == "setoutput" or command.lower() == "so":
            print("setoutput")

        elif command.lower() == "help" or command.lower() == "h":
            print(HELP_MENU)

        else:
            print("No such command. Use help.")

        command = input("pefa\\> ")

################### End Help Menu ###################

def main():   
    print(BANNER) 
    startShell()

if __name__ == '__main__':
    main()
