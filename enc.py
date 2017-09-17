'''Module to carry out decryption and encryption of given file. Contains encrypt and decrypt functions'''
# enc.py

import os, sys, subprocess, re
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from datetime import datetime
from errors import *

#RSA_private = './rsa_key.bin';RSA_public = './rsa_key.pem'
source_files=[os.path.abspath(os.path.join('enc.py')),
             os.path.abspath(os.path.join("my_rsa_key.py")),
			 os.path.abspath(os.path.join("errors.py"))]
			 
def allfiles():
	'''Function checks all files in current folder'''
	allFiles = []
	for root, subfiles, files in os.walk(os.path.abspath(os.getcwd())):
		for name in files:
			allFiles.append(os.path.join(root,name))
	return allFiles
	
def encrypt(filename,message=True):
	'''Function that reads in and encrypts contents of file'''
	filename = os.path.abspath(filename)
	base=''
	if re.search('.',filename): base=filename.split('.')[0]
	RSA_private=base+"/rsa_key.bin"; RSA_public=base+"/rsa_key.pem"
	
	if not os.path.isfile(filename):
		raise FileNotFoundError("File or directory '%s' not found" % filename)
	
	if filename.endswith('.crypt'):
		raise EncryptedOrDecryptedError("File '{}' is already encrypted".format(filename))
		
	if filename in source_files: raise SourceFileError("'{}' is a source file.".format(filename))
		
	# check that source file is present
	for x in source_files: 
		if os.path.abspath(x) not in allfiles(): raise SourceFileMissingError('''Source file '{}' missing in '{}'.\nCannot encrypt "{}".'''.format(x,os.getcwd(),filename))
		
	# create private/public RSA key pair if not exist
	if not os.path.isfile(RSA_private) or not os.path.isfile(RSA_public):
		subprocess.run("python my_rsa_key.py %s" % filename)

	try:
		with open(filename + ".crypt",'wb') as outfile:
			# import public key
			recipient_key = RSA.import_key(open(RSA_public).read())
			session_key = get_random_bytes(16)

			# Encrypt the session key with the public RSA key
			cipher_rsa = PKCS1_OAEP.new(recipient_key)
			#outfile.write(cipher_rsa.encrypt(session_key))
			outfile.write(session_key)

			# Encrypt the data with the AES session key
			cipher_aes = AES.new(session_key, AES.MODE_EAX)
			ciphertext, tag = cipher_aes.encrypt_and_digest(
			  open(filename,'rb').read())
			[ outfile.write(x) for x in (cipher_aes.nonce, tag, ciphertext) ]

	except Exception as error:
		current = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		print ("%s ERROR Something went wrong, %s" % (current,str(error)))
		os.remove(filename + ".crypt")
		return 2
	
	os.remove(filename)
	current = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	if message: print ("%s INFO Done encrypting '%s'." % (current,filename))
	return filename+".crypt"
	
def decrypt(outfile,message=True):
	'''Function that decrypts encrypted file'''
	outfile = os.path.abspath(outfile)
	base=''
	if re.search('.',outfile): base=outfile.split('.')[0]
	RSA_private=base+"/rsa_key.bin"; RSA_public=base+"/rsa_key.pem"
	
	if not os.path.isfile(outfile):
		raise FileNotFoundError("File or directory '%s' not found" % outfile)
		
	if not outfile.endswith('.crypt'):
		raise EncryptedOrDecryptedError("File '{}' already decrypted".format(outfile))
	
	# check that source file is present
	for x in source_files:
		if os.path.abspath(x) not in allfiles():
			raise SourceFileMissingError('''Source file '{}' missing. Cannot decrypt "{}"'''.format(x,outfile))
	
	# create private/public RSA key pair if not exist
	if not os.path.isfile(RSA_private) or not os.path.isfile(RSA_public):
		subprocess.run("python my_rsa_key.py %s" % outfile)
	
	from my_rsa_key import code
	import shutil
	if len(sys.argv) > 1 and sys.argv[1] == '-d': shutil.rmtree('-d')
	data = ''
	
	with open(outfile,'rb') as f:
		# import private key
		private_key = RSA.import_key(
		    open(RSA_private).read(), passphrase=code)
			
		enc_session_key, nonce, tag, ciphertext = \
		  [f.read(x) for x in (16, 16, 16, -1)]	
		
		# Decrypt session key with the private RSA key
		cipher_rsa = PKCS1_OAEP.new(private_key)
		#session_key = cipher_rsa.decrypt(enc_session_key)
		session_key=enc_session_key
		
		# Decrypt data with AES session key
		cipher_aes = AES.new(session_key,AES.MODE_EAX,nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)

		with open(outfile.replace(".crypt",''),'wb') as fin:
			fin.write(data)
		
	os.remove(outfile)
	if os.path.isfile("./rsa_key.pem"): os.remove("./rsa_key.pem")
	if os.path.isfile("./rsa_key.bin"): os.remove("./rsa_key.bin")
	current = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	if message: print ("%s INFO Done decrypting '%s'." % (current,outfile))
	
	return outfile.replace(".crypt","")

def _main():
	args = sys.argv[1:]
	
	if len(args) < 1:
		print ("Usage: ./encrypt_and_decrypt [(-e|-d)] file(s)")
		return 1
	
	if args[0] == '-d':
		for Tfiles in args[1:]:
			decrypt(Tfiles)
			
			
	elif args[0] == '-e':
		for Tfiles in args[1:]:
			encrypt(Tfiles)
			
	else:
		choice = input("Do you want to (E)ncrypt or (D)ecrypt? ")
		if choice == 'E' or choice == 'e':
			for Tfiles in args:
				encrypt(Tfiles)
					
		elif choice == 'D' or choice == 'd':
			for Tfiles in args:
				decrypt(Tfiles)
					
		else: print ("Invalid choice. Please retry.")
		
if __name__ == '__main__':
	_main()