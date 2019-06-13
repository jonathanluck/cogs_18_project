import os
import random
if(not os.path.isdir("test_files")):
    os.mkdir("test_files")
os.chdir("test_files")
for i in range(0,10):
    l = random.randint(1,2**23)
    outf = open("test_file_{}.bin".format(i),"wb")
    data = random.randint(0,256).to_bytes(1,"big")*l if random.randint(0,2) else os.urandom(l)
    outf.write(data)
    outf.close()
