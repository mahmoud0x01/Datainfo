#!/usr/bin/python
import os
import sys
import argparse
import base64
from subprocess import call 
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

system = os.uname()
if system:
	print R + "your system is {0}".format(system)
else:
	stderr = sys.stderr()
	stderr.write("Error your system is non unix-like / gnu-linux system")
if os.geteuid() != 0:
	print >> sys.stderr, "You Need ROOT permisssions for this application to work proberly !"

def banner():
                                        
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
	print R +""" 		  # by mahmoudadel - facebook.com/0x0ff1    """
	print B + """													



                                            
"""

def parser_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()
def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \rpython ' + sys.argv[0] + " -in example.txt --hash sha-256 -a base64 -o example.txt")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-integrity', '--hash', help="check file integrity with hash functions",choices=["sha256","sha224","sha512","md5","sha1","sha384"])
    parser.add_argument('-in', '--input', help='imput file to check')
    parser.add_argument('-e','--encode',help="encode file with encoding algorithms",choices=["base64","base32","base16"])
    parser.add_argument('-o', '--output', help='Save the hash to text file')
    parser.add_argument('-r','--random',help="simple crypto PRNG random number generator",type=int,choices=[16,32,64,128,256,512,1024,2048,4096,8192])
    parser.add_argument('-d','--decode',help='decode a file',choices=["base64","base32","base16"])
    parser.add_argument('-v','--verbose',help='increase output verbosity',action='store_true')
    global hash ,input , output , encode ,decode, random, verbose
    args = parser.parse_args()
    hash = args.hash
    input = args.input
    output = args.output
    encode = args.encode
    decode = args.decode
    random = args.random
    verbose = args.verbose
    return args
def hashfunc():
	checkfileexist = os.path.isfile(input)
	if checkfileexist==1:
		pass
	else:
		print >> sys.stderr,B + "input file isnt exist !" + R + " [+] exiting"
		sys.exit()
	file = open(input,'r')
	file = file.read()
	import hashlib
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
		print >> sys.stderr,R + "file" + G + " " + input + " " + "is not exist"  + B + " " + "[!] now exiting"
		sys.exit()
	file = open(input,'r+w')
	fileread = file.read()
	if decode:
		print "%s%s[+]%s decoding"%(R,G,B)
		os.system('sleep 2')
		if (os.path.splitext(input)[-1])==".encoded":
			print ("file is encoded now decoding")
			print R + "[!]warning if the file encoding is already unknown the app will corrupt it"
			os.system('sleep 2')
			if decode=="base64":  ##base64 decoding
				filereadecoded = base64.b64decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "OutPut : " + str(newfilename)
			if decode=="base32":  ##base32 decoding
				filereadecoded = base64.b32decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "OutPut : " + str(newfilename)
			if decode=="base16":  ##base16 decoding
				filereadecoded = base64.b16decode(fileread)
				file = open(input,'w')
				file.write(filereadecoded + "\n")
				newfilename = os.path.splitext(str(input))[0]
				os.rename(str(input),str(newfilename))
				print "InputFile : " + str(input)
				print "OutPut : " + str(newfilename)
		else:
			print "error file name string didnt end with 'encoded' do you mean --encoding ?"
			print R + "[+] exiting"
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
			print "OutPut : " + str(newfilename)
		if encode=="base32":  #base 32 encoding
			filereadencoded = base64.b32encode(fileread)
			file = open(input,'w')
			file.write(filereadencoded + "\n")
			newfilenamea = input + ".encoded"
			newfilename = os.path.basename(str(newfilenamea))
			os.rename(str(input),str(newfilenamea))
			print "InputFile : " + str(input)
			print "OutPut : " + str(newfilename)
		if encode=="base16":     # base 16 encoding
			filreadencoded = base64.b16encode(fileread)
			file = open(input,'w')
			file.write(filereadencoded + "\n")
			newfilenamea = input + ".encoded"
			newfilename = os.path.basename(str(newfilenamea))
			os.rename(str(input),str(newfilenamea))
			print "InputFile : " + str(input)
			print "OutPut : " + str(newfilename)
	file.close()
def pseurand():
	os.system('sleep 1.5') # for style only  ^^
	ifencode = raw_input("do you want to encode the random bytes with base64 ? " + R + " [y/n] ")
	if ifencode=="y":  # base64 encode to the random generated data
		randomnum = os.urandom(random).encode("base64")
		if verbose:
			print R + "random number is : " + B + randomnum
	else:
		randomnum = os.urandom(random)  # ascii encoding to random generated data
	if output:
		file = open(output,'w')
		file.write(randomnum + "") # write random data to file 

# main function
def main():
	banner()
	parse_args()
	if hash and encode and decode:
		print >> sys.stderr, B + " Error you cant use encoding and hash functions at one time " + R + " [!] exiting"
		sys.exit()
	if hash and random :
		print >> sys.stderr, B + " Error you cant use random and hash functions at one time" + R + " [!] exiting"
		sys.exit()
	if random and (encode or decode):
		print >> sys.stderr, B + " Error you cant use random and encoding functions at one time" + R + " [!] exiting"
		sys.exit()
	if hash:
		hashfunc()
	if encode or decode:
		encodefunc()
	if random:
		pseurand()
if __name__ == '__main__':main()
