import Crypto.Cipher, Crypto.Random, Crypto.Util.Padding
from Crypto.Cipher import AES
import hashlib
import getpass
import struct
import os
import lzma


#https://pycryptodome.readthedocs.io/en/latest/src/api.html
#https://docs.python.org/3/library/hashlib.html
#https://docs.python.org/3.7/library/getpass.html



#becauses files need magic headers
MAGIC_HEADER = b'ASDF'

#16 byte salts an block sizes
SALT_SIZE = 16
AES_BLOCK_SIZE = 16

#because I'm tired of 
UNSIGNED_HALF_WORD = "<H"
UNSIGNED_WORD = "<I"
#scrypt is used to store the hash within the encrypted archive
#to prevent brute force
SCRYPT_N = 2**13
SCRYPT_R = 30
SCRYPT_P = 2

#the AES key will be derived using pbkdf2
PBKDF2_HASH_NAME = "sha256"
PBKDF2_N = 2**17

class EncryptedArchive:
    def __init__(self):
        """
        Constructor for a CryptArchive object

        """
        self.file_data = {}
        self.file_sizes = {}
        self.file_names = []

    def create_archive(self, password, out_file_name, file_names):
        """Creates a new archive
        password -- string -- password used to encrpyt the archive
        file_names -- list of strings -- of files names to include in the archive
        out_file_name -- string -- file name of the location/file where the archive is written to
        """
        #for performance reasons, we'll buffer the output in memory,
        #then write it to a file all at once
        #set up the variables we'll need later
        out_file_bytes = b''
        header_bytes = b''
        file_list_bytes = b''
        file_data_bytes = b''
        password = bytes(password,'utf-8')
        num_files = len(file_names)

        #open the appropriate files
        out_file_obj = open(out_file_name, 'wb+')
        file_objs = {os.path.basename(fn):open(fn, "rb") for fn in file_names}
        file_sizes = {os.path.basename(fn):os.stat(fn).st_size for fn in file_names}
        file_names = list(map(os.path.basename, file_names))

        #generate some random salts for the password hash and the key-derivation
        scrypt_salt = Crypto.Random.get_random_bytes(16)
        pbkdf2_salt = Crypto.Random.get_random_bytes(16)

        #hash the password using a strong, slow hash function
        #slow hash functions let us make brute forcing time/resource-consuming
        scrypt_password_hash = hashlib.scrypt(password,
                                       salt=scrypt_salt,
                                       n = SCRYPT_N,
                                       r = SCRYPT_R,
                                       p = SCRYPT_P)

        #write the header into the output bytes
        header_bytes += MAGIC_HEADER
        header_bytes += scrypt_salt
        header_bytes += scrypt_password_hash
        header_bytes += pbkdf2_salt

        #generate the file information and file data sections
        num_files_bytes = struct.pack(UNSIGNED_HALF_WORD, num_files)
        file_list_bytes += num_files_bytes
        for fn in file_names:
            fn_len_bytes = struct.pack(UNSIGNED_HALF_WORD, len(fn))
            file_len = file_sizes[fn]
            file_len_bytes = struct.pack(UNSIGNED_WORD, file_len)
            file_list_bytes += fn_len_bytes + file_len_bytes + bytes(fn,"utf-8")
            file_data_bytes += file_objs[fn].read()
            print("Read: {}  Size: {}".format(fn,file_len))
        print("Files read. Compressing now... Please be patient")
        #compress the data
        file_data_bytes = lzma.compress(file_data_bytes)

        #generate the encryption key
        aes_key = hashlib.pbkdf2_hmac(PBKDF2_HASH_NAME, password, pbkdf2_salt, PBKDF2_N)
        
        #adapted from https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
        #use an AEAD algorithm to provide integrity/authenticity over the non-encrypted headers
        aes_obj = AES.new(aes_key, AES.MODE_EAX, nonce=pbkdf2_salt)
        aes_obj.update(header_bytes)
        file_list_len_bytes = struct.pack(UNSIGNED_WORD, len(file_list_bytes))
        encrypted_file_data, mac  = aes_obj.encrypt_and_digest(file_list_len_bytes +
                                                               file_list_bytes +
                                                               file_data_bytes)

        #write everything to the file
        out_file_obj.write(header_bytes)
        out_file_obj.write(encrypted_file_data)
        out_file_obj.write(mac)
        out_file_obj.close()

    def load_archive(self, password, archive_file_name):
        """Loads an archive into memory,
        password -- string -- password used to encrypt the archive
        archive_file_name -- string -- file name of the archive to load
        """
        #set up the password, file handles, and separate the file into correct variables
        password = bytes(password,'utf-8')
        archive_file_bytes = open(archive_file_name, 'rb').read()
        header_bytes = archive_file_bytes[:100]
        file_data_bytes = archive_file_bytes[100:-16]
        mac = archive_file_bytes[-16:]
        pbkdf2_salt = header_bytes[-16:]

        #generate the decryption key based on the password
        aes_key = hashlib.pbkdf2_hmac(PBKDF2_HASH_NAME, password, pbkdf2_salt, PBKDF2_N)
        
        #adapted from https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html
        #decrypt the file, and verify the integrity/authenticity of the unencrypted headers
        aes_obj = AES.new(aes_key, AES.MODE_EAX, nonce=pbkdf2_salt)
        aes_obj.update(header_bytes)
        try:
            unenc_file_data_bytes = aes_obj.decrypt_and_verify(file_data_bytes, mac)
        except ValueError:
            raise ValueError("Wrong password or file was tampered with")

        #parse out the file information section, setting up bytestrings of data
        file_list_len = struct.unpack(UNSIGNED_WORD, unenc_file_data_bytes[:4])[0]
        num_files = struct.unpack(UNSIGNED_HALF_WORD, unenc_file_data_bytes[4:6])[0]
        file_list_data = unenc_file_data_bytes[6: 4 + file_list_len]
        unenc_file_data_bytes = lzma.decompress(unenc_file_data_bytes[4 + file_list_len:])

        #separate each file, mapping its file length and data to its name
        for i in range(num_files):
            fn_len, file_len = struct.unpack("<HI", file_list_data[:6])
            #print(fn_len,file_len, file_list_data)
            file_list_data = file_list_data[6:]
            fn = file_list_data[:fn_len].decode("utf-8")
            file_list_data = file_list_data[fn_len:]
            self.file_names.append(fn)
            self.file_sizes[fn] = file_len
            self.file_data[fn] = unenc_file_data_bytes[:file_len]
            unenc_file_data_bytes = unenc_file_data_bytes[file_len:]

    def display_files(self):
        """Prints out file names and sizes
        """
        #set it up so all the file sizes start lined up
        max_filename_len = len(max(self.file_names, key=lambda x: len(x)))

        #print each file with its size with a set of spaces to line things up nicely
        for fn in self.file_names:
            fn_len = len(fn)
            spaces = max_filename_len - fn_len + 1
            print("{}:{}{} bytes".format(fn, " " * spaces, self.file_sizes[fn]))

    def extract_file(self, filename, directory="."):
        """Extracts a given file from the archive.
        Can only be called on a file in the archive after load_archive has been called
        filename -- string -- filename within the archive to extract
        directory -- string -- where the file should be extracted to (default: current directory)
        """
        out_file = open(os.path.join(directory,filename), 'wb')
        out_file.write(self.file_data[filename])
        out_file.close()


