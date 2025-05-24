#A simple script that makes a file path parameter to wrap around 
#the export_pcode.py script
#@nhagan2468 
#@category PCode 

# EDIT THIS!!! Change this to the appropriate location for the output
outFile = "\\Path\\to\\output\\file"

# Set the location as the argument and then run the export_pcode script
setScriptArgs([outFile])
runScript("export_pcode.py")


    



