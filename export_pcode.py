#A simple script that takes a binary imported into Ghidra and will 
#export the pcode to a text file with a .pcode file extenstion
#@nhagan2468 
#@category PCode

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
