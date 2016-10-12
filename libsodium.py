#Mateo Zoto
#CPSC 526 // Homework 2
#This file encrypts a file using the NACL libraries and PYNACL
#usage python encryption.py encrypt plaintextfile ciphertextfile
#      python decrypt.py decrypt ciphertextfile plaintextfile

import nacl.hash
import nacl.encoding
import nacl.secret
import nacl.utils

import sys
import getpass
import re
import os.path
import binascii

def encrypt(filename):
    password = getpass.getpass("Enter passphrase:")
    key = nacl.hash.sha256(password, encoder=nacl.encoding.RawEncoder)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    plaintext_fh = open(filename, 'r')
    plaintext = plaintext_fh.read()
    plaintext_fh.close()
    box = nacl.secret.SecretBox(key)
    return box.encrypt(plaintext, nonce, encoder=nacl.encoding.Base64Encoder)

def decrypt(filename):
    password = getpass.getpass("Enter passphrase:")
    key = nacl.hash.sha256(password, encoder=nacl.encoding.RawEncoder)
    fh = open(filename, 'r')
    bin_ciphertext = binascii.a2b_base64(fh.read())
    fh.close()
    nonce = bin_ciphertext[0:24]
    ciphertext = bin_ciphertext[24:]
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext, nonce)

def main(argv): 
	if (argv[1] == "encrypt"):
		plaintextfile = argv[2]
		ciphertextfile = argv[3]
		print (ciphertextfile)
		ciphertext = encrypt(plaintextfile)
		file = open(ciphertextfile,'w')
		file.write(ciphertext)
		file.close()
	elif (argv[1] == "decrypt"):
		ciphertextfile  = argv[2]
		plaintextfile = argv[3]
		plaintext = decrypt(ciphertextfile)
		file = open(plaintextfile,'w')
		file.write(plaintext)
		file.close()
	else:
		print("invalid arguments")
	return

if __name__ == '__main__':
    sys.exit(main(sys.argv))
