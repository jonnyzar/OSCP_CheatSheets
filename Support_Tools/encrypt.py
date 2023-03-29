from Crypto.Cipher import AES
import os
import sys

def main():
    #ok storing key in same file is a bad idea but it is as an example here
    #key = b'Sixteen byte key'
    encrypt_file(sys.argv[1].encode(), sys.argv[2])


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """Encrypts a file using AES (CBC mode) with the given key.

    Args:
        key (str): The encryption key - a string that must be either 16, 24, or 32 bytes long.
        in_filename (str): The name of the input file to encrypt.
        out_filename (str, optional): The name of the output file. If not specified, will be the same as the input file with '.enc' appended.
        chunksize (int, optional): Sets the size of the chunk which the function uses to read and encrypt the file. Larger chunk sizes can be faster for some files and machines.

    Returns:
        None
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

if __name__=='__main__':
    main()
