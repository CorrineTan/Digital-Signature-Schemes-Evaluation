#install ed25519
#pip install ed25519 
import ed25519
import time
import sys
import hashlib
# signing_key, verifying_key = ed25519.create_keypair()


def ed25519test(filename):
	time1 = 0
	time2 = 0
	time3 = 0
	with open(filename) as f:
		for line in f:
			message = str.encode(line)
			digest = hashlib.sha256(message).digest()

# message = str.encode(messa)

			keygenestart = time.time()
			signing_key, verifying_key = ed25519.create_keypair()
			keygeneend = time.time()	
			time1 += keygeneend - keygenestart
# print("Time used to generate a key pair is", keygeneend - keygenestart)

	# open("my-secret-key","wb").write(signing_key.to_bytes())
# vkey_hex = verifying_key.to_ascii(encoding="hex")
# print("the private key is", signing_key.to_ascii(encoding="hex"))
# print("the public key is", vkey_hex)

			signstart = time.time()
			signature = signing_key.sign(digest, encoding = "base64")
			signend = time.time()
			time2 += signend - signstart
# print("the signature is", signature)
# print("Time used to generate a signature is", signend - signstart)



# verify:
			verifystart = time.time()
			try:
  				verifying_key.verify(signature, digest, encoding="base64")
  				# print("signature is good!")
			except ed25519.BadSignatureError:
  				print("signature is bad!")
			verifyend = time.time()
			time3 += verifyend - verifystart
# endtime = time.time()
	return time1, time2, time3

if __name__ == '__main__':
	# time1 = 0
	# time2 = 0 
	# time3 = 0
	# filename = sys.argv[1:]
	# dire = "".join(sys.argv[1:])
	# fnames = [os.path.join(dire,x) for x in os.listdir(dire)]
	# print(fnames)
	# for filename in fnames:
	time1, time2, time3 = ed25519test("".join(sys.argv[1:]))
	totaltime = time1 + time2 +time3
	# time1 += tim1
	# time2 += tim2
	# time3 += tim3
	print("The time used to generate key pairs:",time1)
	print("The time used to sign messages:",time2)
	print("The time used to verify messages:",time3)
	print("Total time:",totaltime)