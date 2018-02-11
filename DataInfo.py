#!/usr/bin/python
# coding: utf-8
import hashlib
import logging
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.PublicKey import RSA
import os
import sys
import argparse
import base64
import getpass
def sysinfo():
	global G,Y,B,R,W
	system = os.uname()  # define the system 
	if system:
		G = '\033[92m'  # green
		Y = '\033[93m'  # yellow
		B = '\033[94m'  # blue
		R = '\033[91m'  # red
		W = '\033[0m'   # white
	return G , Y , B , R , W 
def banner():
              # my banner ;]                          
	print R +"""		 _____        _        _____        __      """
	os.system('sleep 0.2')
	print B +"""		|  __ \      | |      |_   _|      / _|     """
	os.system('sleep 0.2')  
	print Y +"""		| |  | | __ _| |_ __ _  | |  _ __ | |_ ___  """
	os.system('sleep 0.2')
	print R +"""		| |  | |/ _` | __/ _` | | | | '_ \|  _/ _ \ """
	os.system('sleep 0.2')
	print B +"""		| |__| | (_| | || (_| |_| |_| | | | || (_) |"""
	os.system('sleep 0.2')
	print B +"""		|_____/ \__,_|\__\__,_|_____|_| |_|_| \___/ """
	os.system('sleep 0.2')
	print R +""" 		  # coded by mahmoudadel - facebook.com/0x0ff1    """
	print W + """													



                                            
"""

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg )
    sys.exit()
def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \rpython ' + sys.argv[0] + " -in file -o file -enc aes-256-cfb -r 1024")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-enc','--encrypt', help="encrypt a file with a cipher - Usage = '-enc' $Cipher")
    parser.add_argument('-dec','--decrypt', help="decrypt a file with the encryption algorithm")
    parser.add_argument('-k','--key', help="key to use for encryption ! NOTE : if no key specify random one will be generated")
    parser.add_argument('-integrity', '--hash', help="check file integrity with hash functions")
    parser.add_argument('-in', '--input', help='imput file')
    parser.add_argument('-e','--encode',help="encode file with encoding algorithms")
    parser.add_argument('-o', '--output', help='output file')
    parser.add_argument('-r','--random',help="simple random data generator",type=int)
    parser.add_argument('-d','--decode',help='decode a file')
    global hash ,input , output , encode ,decode, random, encrypt, decrypt, keyarg, rsa, args # global the args variables
    args = parser.parse_args()
    return args
def hashfunc():
	checkfileexist = os.path.isfile(input)
	if checkfileexist==1:
		pass
	else:
		print >> sys.stderr,R + "[!]" + W + "input file is not exist ![+] exiting"
		sys.exit()
	file = open(input,'r')
	file = file.read()
	md5 = hashlib.md5(file)
	md5 = md5.hexdigest()
	sha256 = hashlib.sha256(file)
	sha256 = sha256.hexdigest()
	sha224 = hashlib.sha224(file)
	sha224 = sha224.hexdigest()
	sha512 = hashlib.sha512(file)
	sha512 = sha512.hexdigest()
	sha384 = hashlib.sha384(file)
	sha384 = sha384.hexdigest()
	sha1 = hashlib.sha1(file)
	sha1 = sha1.hexdigest()
	if hash:
		filename = os.path.basename(input)
		if (hash=="sha256"):
			print ("file : " + filename + "\n" + """%s
				hash is :"""%(R) + sha256)
			if output:
				f = open(output,'w')
				f.write(sha256 + "\n")
		if(hash=="sha1"):
			print("file : " + filename + "\n" + """%s
				hash is : """%(R) + sha1)
			if output:
				f = open(output,'w')
				f.write(sha1 + "\n")
		if(hash=="sha224"):
			print ("file : " + filename + "\n" + """%s
				hash is :"""%(R) + sha224)
			if output:
				f = open(output,'w')
				f.write(sha224 + "\n")
		if (hash=="md5"):
			print ("file : " + filename + "\n" + """%s
				hash is :"""%(R) + md5)
			if output:
				f = open(output,'w')
				f.write(md5 + "\n")
		if (hash=="sha512"):
			print ("file : " + filename + "\n" + """%s
				hash is :"""%(R) + sha512)
			if output:
				f = open(output,'w')
				f.write(sha512 + "\n")
		if (hash=="sha384"):
			print ("file : " + filename + "\n" + """%s
				hash is :"""%(R) + sha384)
			if output:
				f = open(output,'w')
				f.write(sha384 + "\n")
def encodefunc():
	checkfileexist = os.path.isfile(input)
	if checkfileexist==1:
		pass
	else:
		print >> sys.stderr,R + "[!]" + "file" + G + " " + input + " " + "is not exist"  + W + " " + "[!] now exiting"
		sys.exit()
	file = open(input,'r+w')
	fileread = file.read()
	if decode:
		print "%s%s[+]%s decoding"%(R,G,B)
		os.system('sleep 2')
		if (os.path.splitext(input)[-1])==".encoded":
			print ("file is encoded now decoding")
			print R + "[!]" + W + "warning if the file encoding is already unknown the app will corrupt it"
			os.system('sleep 2')
			if decode=="base64":  ##base64 decoding
				filereadecoded = base64.b64decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "Output : " + str(newfilename)
			if decode=="base32":  ##base32 decoding
				filereadecoded = base64.b32decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "Output : " + str(newfilename)
			if decode=="base16":  ##base16 decoding
				filereadecoded = base64.b16decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "Output : " + str(newfilename)
		else:
			print "error file name string didnt end with 'encoded' do you mean --encoding ?"
			print R + "[!] exiting"
			sys.exit()
	if encode:
		print ("%s%s[+]%s encoding"%(R,B,G))
		os.system('sleep 2')
		if encode=="base64": #base 64 encoding
			filereadencoded = base64.b64encode(fileread)
			file = open(input,'w')
			file.write(filereadencoded + "\n")
			newfilenamea = input + ".encoded"
			newfilename = os.path.basename(newfilenamea)
			os.rename(str(input),str(newfilenamea))
			print "InputFile : " + str(input)
			print "Output : " + str(newfilename)
		if encode=="base32":  #base 32 encoding
			filereadencoded = base64.b32encode(fileread)
			file = open(input,'w')
			file.write(filereadencoded + "\n")
			newfilenamea = input + ".encoded"
			newfilename = os.path.basename(str(newfilenamea))
			os.rename(str(input),str(newfilenamea))
			print "InputFile : " + str(input)
			print "Output : " + str(newfilename)
		if encode=="base16":     # base 16 encoding
			filreadencoded = base64.b16encode(fileread)
			file = open(input,'w')
			file.write(filereadencoded + "\n")
			newfilenamea = input + ".encoded"
			newfilename = os.path.basename(str(newfilenamea))
			os.rename(str(input),str(newfilenamea))
			print "InputFile : " + str(input)
			print "Output : " + str(newfilename)
	file.close()
def pseurand():
	os.system('sleep 1') # for style only  ^^
	ifencode = raw_input("do you want to encode the random bytes with base64 ? " + R + " [y/n] ")
	if ifencode=="y":  # base64 encode to the random generated data
		randomnum = os.urandom(random).encode("base64")
	else:
		randomnum = os.urandom(random)  # ascii encoding to random generated data
	if output:
		file = open(output,'w')
		file.write(randomnum + "") # write random data to file 
		if verbose:
			print R + '[+]' "random number is : " + '\n' + W + randomnum
	else:
		print B + '[+]' + "Random data is : " + '\n' + W + randomnum
class AESCIPHER():
	def __init__(self,**kwargs):
		self.arguments = kwargs
		global pad,unpad,BS
		BS = 16 # block size 
		pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
		unpad = lambda s : s[0:-ord(s[-1])]
		self.arguments["key"]
		self.arguments["plaintext"]
		self.arguments["ciphertext"]
	def encryptCBC(self):
		iv = Random.get_random_bytes(16)
		plaintext = pad(self.arguments["plaintext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		encryption = AES.new(key, AES.MODE_CBC, iv)
		if encode == "base64":
			return base64.b64encode(iv + encryption.encrypt(plaintext))
		else:
			return (iv + encryption.encrypt(plaintext))
	def decryptCBC(self):
		if decode == "base64":
			ciphertext = base64.b64decode(self.arguments["ciphertext"])
		else:
			ciphertext = (self.arguments["ciphertext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		iv = ciphertext[:16]
		encryption = AES.new(key, AES.MODE_CBC, iv)
		return unpad(encryption.decrypt( ciphertext[16:] ))
	def encryptOFB(self):
		iv = Random.get_random_bytes(16)
		plaintext = pad(self.arguments["plaintext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		encryption = AES.new(key, AES.MODE_OFB, iv)
		if encode == "base64":
			return base64.b64encode(iv + encryption.encrypt(plaintext))
		else:
			return (iv + encryption.encrypt(plaintext))
	def decryptOFB(self):
		if decode == "base64":
			ciphertext = base64.b64decode(self.arguments["ciphertext"])
		else:
			ciphertext = (self.arguments["ciphertext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		iv = ciphertext[:16]
		encryption = AES.new(key, AES.MODE_OFB, iv)
		return unpad(encryption.decrypt( ciphertext[16:] ))
	def encryptCFB(self):
		iv = Random.get_random_bytes(16)
		plaintext = pad(self.arguments["plaintext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		encryption = AES.new(key, AES.MODE_CFB, iv)
		if encode == "base64":
			return base64.b64encode(iv + encryption.encrypt(plaintext))
		else:
			return (iv + encryption.encrypt(plaintext))
	def decryptCFB(self):
		if decode == "base64":
			ciphertext = base64.b64decode(self.arguments["ciphertext"])
		else:
			ciphertext = (self.arguments["ciphertext"])
		key = hashlib.sha256(self.arguments["key"].encode('utf-8')).digest()
		iv = ciphertext[:16]
		encryption = AES.new(key, AES.MODE_CFB, iv)
		return unpad(encryption.decrypt( ciphertext[16:] ))
def crypto(keyarg):
	checkfileexist = os.path.isfile(input)
	if checkfileexist==1:
		pass
	else:
		print >> sys.stderr,R + '[!]' + "file : " + W + " " + input + " " + "is not exist" + " " + "[!] now exiting"
		sys.exit()
	file = open(input,'r+w')
	fileread = file.read()
	if encrypt == 'AES-256-CFB' or encrypt == 'aes-256-cfb':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-CFB encryption password : ")
			if keyarg:
				pass
			else:
				keyarg = (Random.get_random_bytes(256)).encode("base64")
				keyexportpath = raw_input(B + "[!]" + "Random key generated Enter export path ? :")
				if os.path.isfile(keyexportpath)==1:
					file = open(keyexportpath, 'wb')
					file.write(keyarg)

		aes = AESCIPHER(key=keyarg,plaintext=fileread,ciphertext=None).encryptCFB()
		print B + "[+]" + W + "encrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + W + "do you want to overwrite input file data :? [y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilenamea = input + ".encrypted"
				newfilename = os.path.basename(newfilenamea)
				os.rename(str(input),str(newfilenamea))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes
	if decrypt == 'AES-256-CFB' or decrypt == 'aes-256-cfb':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-CFB decryption password : ")
			if keyarg:
				pass
			else:
				print R + "[!]" + "Error in key input now exiting"
				sys.exit()

		aes = AESCIPHER(key=keyarg,ciphertext=fileread,plaintext=None).decryptCFB()
		print B + "[+]" + W + "decrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + "do you want to overwrite file data :? " + W + "[y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilename = os.path.splitext(str(input))[0]
				if os.path.splitext(str(input))[-1] == ".encrypted":
					os.rename(str(input),str(newfilename))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes
	if encrypt == 'AES-256-CBC' or encrypt == 'aes-256-cbc':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-CBC encryption password : ")
			if keyarg:
				pass
			else:
				keyarg = (Random.get_random_bytes(256)).encode("base64")
				keyexportpath = raw_input(B + "[!]" + "Random key generated Enter export path ? :")
				if os.path.isfile(keyexportpath)==1:
					file = open(keyexportpath, 'wb')
					file.write(keyarg)
		aes = AESCIPHER(key=keyarg,plaintext=fileread,ciphertext=None).encryptCBC()
		print B + "[+]" + W + "encrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + W + "do you want to overwrite file data :? [y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilenamea = input + ".encrypted"
				newfilename = os.path.basename(newfilenamea)
				os.rename(str(input),str(newfilenamea))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes 
	if decrypt == 'AES-256-CBC' or decrypt == 'aes-256-cbc':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-CBC decryption password : ")
			if keyarg:
				pass
			else:
				print R + "[!]" + "Error in key input now exiting"
				sys.exit()
		aes = AESCIPHER(key=keyarg,ciphertext=fileread,plaintext=None).decryptCBC()
		print B + "[+]" + W + "decrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + W + "do you want to overwrite file data :? [y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilename = os.path.splitext(str(input))[0]
				if os.path.splitext(str(input))[-1] == ".encrypted":
					os.rename(str(input),str(newfilename))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes
	if encrypt == 'AES-256-OFB' or encrypt == 'aes-256-ofb':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-OFB encryption password : ")
			if keyarg:
				pass
			else:
				keyarg = (Random.get_random_bytes(256)).encode("base64")
				keyexportpath = raw_input(B + "[!]" + "Random key generated Enter export path ? :")
				if os.path.isfile(keyexportpath)==1:
					file = open(keyexportpath, 'wb')
					file.write(keyarg)
		aes = AESCIPHER(key=keyarg,plaintext=fileread,ciphertext=None).encryptOFB()
		print B + "[+]" + W + "encrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + W + "do you want to overwrite file data :? [y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilenamea = input + ".encrypted"
				newfilename = os.path.basename(newfilenamea)
				os.rename(str(input),str(newfilenamea))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes 
	if decrypt == 'AES-256-OFB' or decrypt == 'aes-256-ofb':
		if keyarg:
			pass
		else:
			keyarg = getpass.getpass(B + "[!]" "Enter AES-OFB decryption password : ")
			if keyarg:
				pass
			else:
				print R + "[!]" + "Error in key input now exiting"
				sys.exit()
		aes = AESCIPHER(key=keyarg,ciphertext=fileread,plaintext=None).decryptOFB()
		print B + "[+]" + W + "decrypting"
		os.system('sleep 0.8')
		if output:
			file = open(output, 'wb')
			file.write(aes)
		else:
			checkwantwrite = raw_input(B + "[?]" + W + "do you want to overwrite file data :? [y/n]")
			if checkwantwrite=='y':
				file = open(input, 'w')
				file.write(aes)
				newfilename = os.path.splitext(str(input))[0]
				if os.path.splitext(str(input))[-1] == ".encrypted":
					os.rename(str(input),str(newfilename))
			if checkwantwrite=='n':
				print B + '[+]' + W + 'encrypted data : ' + '\n' + aes

# main function
def main():
	sysinfo()
	if encode or decode and (encrypt or decrypt):
		banner()
		crypto(keyarg=keyarg)
	if hash and encode and decode:
		print >> sys.stderr, R + '[!]' + W + " Error you cant use encoding and hash functions at one time"
		sys.exit()
	if hash and random :
		print >> sys.stderr, R + '[!]' + W + " Error you cant use random and hash functions at one time"
		sys.exit()
	if random and (encode or decode):
		print >> sys.stderr, R + '[!]' + W + " Error you cant use random and encoding functions at one time"
		sys.exit()
	if random and (encrypt or decrypt):
		print >> sys.stderr, R + '[!]' + W + " Error you cant use random and encryption functions at one time"
		sys.exit()
	if hash and (encrypt or decrypt):
		print >> sys.stderr, R + '[!]' + W + " Error you cant use hash and encryption functions at one time"
		sys.exit()
	if hash:
		banner()
		hashfunc()
	if (encode or decode) and not (encrypt or decrypt):
		banner()
		encodefunc()
	if random:
		banner()
		pseurand()
if __name__ == '__main__': 
	parse_args()
	hash = args.hash
	input = args.input
	output = args.output
	encode = args.encode
	decode = args.decode
	random = args.random
	encrypt = args.encrypt
	decrypt = args.decrypt
	keyarg = args.key
	main()