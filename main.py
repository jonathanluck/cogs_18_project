import os
import getpass
from EncryptedArchive import EncryptedArchive


enc_or_dec = input("(E)ncrypt and archive or (D)ecrypt and unarchive: ")
if (enc_or_dec.lower().startswith("encrypt") or enc_or_dec.lower().startswith("e")):
    #this is what happens when you put on a character limit on lines
    #get the directory to archive
    directory = input("Please provide a directory to archive. "
                      "Note that all files in that directory will be archived, "
                      "but not subdirectories. "
                      "Directory: ")
    if(not os.path.isdir(directory)):
        print("Invalid directory")
        exit(1)
    else:
        #get the password and output file name
        password = getpass.getpass()
        output_file_name = input("Output archive filename: ")
        #pull out all the files in the directory, join with relative dir path
        files = [os.path.join(directory, fn)
                 for fn in os.listdir(directory)
                 if os.path.isfile(os.path.join(directory, fn))]
        #archive it 
        enc = EncryptedArchive()
        enc.create_archive(password, output_file_name, files)
        print("Successfully created {}".format(output_file_name))
elif (enc_or_dec.lower().startswith("decrypt") or enc_or_dec.lower().startswith("d")):
    #get the archive filename 
    archive_fn = input("Archive filename: ")
    password = getpass.getpass()
    #decrypt and unarchive it
    enc = EncryptedArchive()
    enc.load_archive(password, archive_fn)
    #show the files in the archive
    enc.display_files()
    try:
        while True:
            #extract the file
            fn = input("Which file would you like to extract? Press ctrl+c to exit. File: ")
            directory = input("What directory would you like to extract {} to?"
                              "('.' for current dir): ".format(fn))
            enc.extract_file(fn, directory)
            print("Successfully extracted {}".format(fn))
            
    except KeyboardInterrupt:
        exit(1)

else:
    print("Invalid operation")
    exit(1)
