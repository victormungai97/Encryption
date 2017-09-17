'''Module containing possible errors during encryption and decryption'''
# errors.py

class FileNotFoundError(Exception):
	'''Raises error that file doesn't exist'''
	pass

class SourceFileMissingError(Exception):
	'''Raises error that a source file is missing'''
	pass
	
class EncryptedOrDecryptedError(Exception):
	'''Raises error if file is already encrypted or decrypted'''
	pass
	
class SourceFileError(Exception):
	'''Raises error if file is a source file'''
	pass