helpInputFile=open("help.txt", "r").read().splitlines()
helpOutputFile=open("help.c", "w")

helpOutputFile.write("//Warning this file is autogenrated by create_help.py\n");
helpOutputFile.write('#include "help.h"\n');
helpOutputFile.write("#include <stdio.h>\n");
helpOutputFile.write('#define NEWLINE "\\n"\n');
helpOutputFile.write("void print_help() {\n");

for line in helpInputFile:

    line2 = line.replace('"', '\\"');

    helpOutputFile.write("    printf(\"%s\" NEWLINE, \""+line2+"\");\n");

helpOutputFile.write("}\n");
