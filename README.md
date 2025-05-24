# pcode_exporter
A simple Python script to export pcode from a Ghidra project to be used with Ghidra's headlessanalyzer into a text file or with a wrapper inside the Ghidra GUI.
## Background
Ghidra's pcode is an intermediate language that Ghidra (https://github.com/NationalSecurityAgency/ghidra) uses for the imported disassembled binaries to allow common function processing over a multitude of processor architectures. Ghidra's headless mode enables a command line based interface to the program with access to running external scripts on the analyzed binaries. 
## Overview/Requirements
Ghidra by default does not have an export capability that will allow someone to export the pcode directly. This script gives the ability to take a Ghidra program, disassemble the included files, and then export the pcode as text for each function, beginning with the entry point and increasing in address location.  

The two scripts allow the user to export the pcode from the Ghidra GUI itself or using headless mode to allow batch development.

**Note: This project was developed with Ghidra 11.1.1. Your mileage may vary with other Ghidra versions.** 

## Installation
If using in the GUI Ghidra, then the checked out repository must be added to the Script Manager. In Ghidra, open the Script Manager and select the Script Directories icon to open the Bundle Manager. Add the checked out repository as a path. Press the refresh button to ensure that the scripts are imported into the manager. 

## Usage 
### Running Headless 
From the path of your Ghidra analyzeHeadless binary, run `analyzeHeadless <directory_to_Ghidra_project> <ghidra_project_name> -scriptPath <path_to_this_project> -process -postScript export_pcode.py <path_and_output_file_name>`. The program will take the `output_file_name` and append a `.pcode` to the filename when exporting. 

### Running from the GUI
In Ghidra, open the Script Manager. The scripts will be in the PCode Directory on the lefthand side of the manager. Right click on the `pcode_exporter_wrapper.py` script and select to edit the file. In the file, change the string assigned to `outFile` to the location where you would like to save the pcode file. 

## Future Directions
* More work could be done to deal with errors in the running of the script. 
* Add a method to create a pop-up box using Ghidra Bridge instead of manually updating the outFile location when running in the GUI
* Add another parameter to allow the selection if a project exists or if this is a new import
* Add marking/differentiating the different files in the Ghidra project to the output .pcode file
* Add additional file formats other than text file for the output