'''Module to generate private/public RSA key for encryption'''
# my_rsa_key.py

import os,sys,re
from Cryptodome.PublicKey import RSA

code = 'S>nnz.r#PEh8/HY0BNY3@i)Jq\\+KDdwo'

def open_file(filename,file2):
	with open(filename,'wb') as f: f.write(file2)

def funct(folder=None):
	# generate RSA key
	key = RSA.generate(2048)
	# generate private key and write to file
	encrypted_key = key.exportKey(passphrase=code, pkcs=8,
		protection="scryptAndAES128-CBC")
	if folder: 
		open_file(os.path.join(folder,'rsa_key.bin'),encrypted_key)

		# generate public key and write to file
		open_file(os.path.join(folder,'rsa_key.pem'),key.publickey().exportKey())
	else:
		open_file('./rsa_key.bin',encrypted_key)
			
		open_file('./rsa_key.pem',key.publickey().exportKey())

args = sys.argv[1:]
if args:
	for file in args:
		file = os.path.abspath(file)
		if re.search('.',file):
			file = file.split('.')[0]
		# create folders for easy differentiation of each file's encrypted keys
		if not os.path.isdir(file): os.mkdir(file)
		funct(file)

else: funct()
