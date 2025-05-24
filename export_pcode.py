#A simple script that takes a binary imported into Ghidra and will 
#export the pcode to a text file with a .pcode file extenstion
#@nhagan2468 
#@category PCode

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import FunctionManager #CodeUnit, FunctionManager
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from argparse import ArgumentParser

# Get the path to output the pcode to from arguments
args = getScriptArgs();
path = args[0] + ".pcode"
fout = open(path, "w")

# Initialize decompiler interface for the program to decompile the functions
decompInterface = DecompInterface()
decompInterface.openProgram(currentProgram)

# Loop through all functions starting from the entry point address ascending
# Decompile the function and then export the pcode
funcMgr = currentProgram.getFunctionManager()
for func in funcMgr.getFunctions(True):
    decompResults = decompInterface.decompileFunction(func, 60, TaskMonitor.DUMMY)
    highFunction = decompResults.getHighFunction()

    # Get the PCode operations
    pcodeOps = highFunction.getPcodeOps()
    fout.write("++++" + func.getName() + "\n")
    print("++++" + func.getName())

    # Iterate over PCode operations and print them
    for pcodeOp in pcodeOps:
        print(pcodeOp)
        fout.write(pcodeOp.toString() + "\n")

# close the file and get out
fout.close()
