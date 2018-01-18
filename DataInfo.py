#!/usr/bin/python
import os
import sys
import argparse
import base64
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
	print ("""%s

                                            
	 _____        _        _____        __      
	|  __ \      | |      |_   _|      / _| %s%s    
	| |  | | __ _| |_ __ _  | |  _ __ | |_ ___  
	| |  | |/ _` | __/ _` | | | | '_ \|  _/ _ \ %s%s
	| |__| | (_| | || (_| |_| |_| | | | || (_) |
	|_____/ \__,_|\__\__,_|_____|_| |_|_| \___/ %s%s
     # by mahmoudadel - facebook.com/0x0ff1
                                            





		"""%(R,R,B,B,G,W,Y))

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
    global hash ,input , output , encode ,decode, random
    args = parser.parse_args()
    hash = args.hash
    input = args.input
    output = args.output
    encode = args.encode
    decode = args.decode
    random = args.random
    return args
def hashfunc():
	checkfileexist = os.path.isfile(input)
	if checkfileexist==1:
		pass
	else:
		print >> sys.stderr,R + "file" + G + " " + input + " " + "is not exist"  + B + " " + "[!]now exiting"
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
		print >> sys.stderr,R + "file" + input + "isnt exist" + B + "now exiting"
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
	os.system('sleep 3')
	randomnum = os.urandom(random).encode("base64")
	print R + "random number is : " + B + randomnum

# main function
def main():
	banner()
	parse_args()
	if hash:
		hashfunc()
	if encode or decode:
		encodefunc()
	if random:
		pseurand()
if __name__ == '__main__':main()
