import hashlib
import sys

# This tool truncate function name with more than 200 characters because llvm opt does not support them when constructing intra-CFGs.
data = []
with open(sys.argv[1], 'r') as f:
    data  = f.read().splitlines()

replace_table = []
for line in data:
    if line.startswith("define"):
        fun_name =  line.split('@')[1].split('(')[0]
        if len(fun_name) > 200:
            new_fun_name = fun_name[:20] + hashlib.md5(fun_name.encode()).hexdigest() + fun_name[-20:]
            replace_table.append((fun_name, new_fun_name))

#input file
fin = open(sys.argv[1], "rt")
#output file to write the result to
fout = open(sys.argv[1].split('.ll')[0]+"_fix.ll", "wt")
#for each line in the input file
for line in fin:
    #read replace the string and write to output file
    for a,b in replace_table:
        line = line.replace(a, b)
    fout.write(line)
#close input and output files
fin.close()
fout.close()
