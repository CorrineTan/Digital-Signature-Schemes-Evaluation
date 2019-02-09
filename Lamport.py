import hashlib
from binascii import unhexlify, hexlify
from os import urandom
import time
import sys

def sha256(message):
    return hashlib.sha256(message.encode()).hexdigest()

def random_key(n=32):  # returns a 256 bit hex encoded (64 bytes) random number
    return hexlify(urandom(n))

def random_lkey(numbers=256):  # create random lamport signature scheme keypair

    priv = []
    pub = []

    for x in range(numbers):
        a, b = random_key(), random_key()
        priv.append((a, b))
        pub.append((sha256(a), sha256(b)))

    return priv, pub

def sign_lkey(priv, message):  # perform lamport signature

    signature = []
    bin_lmsg = unhexlify(sha256(message))

    z = 0
    for x in range(len(bin_lmsg)):
        l_byte = bin(ord(bin_lmsg[x]))[
                 2:]  # [2:][-1:]      #generate a binary string of 8 bits for each byte of 32/256.

        while len(l_byte) < 8:  # pad the zero's up to 8
            l_byte = '0' + l_byte

        for y in range(0, 8):
            if l_byte[-1:] == '0':
                signature.append(priv[z][0])
                l_byte = l_byte[:-1]
                z += 1
            else:
                signature.append(priv[z][1])
                l_byte = l_byte[:-1]
                z += 1

    return signature

def verify_lkey(signature, message, pub):  # verify lamport signature

    bin_lmsg = unhexlify(sha256(message))
    verify = []
    z = 0

    for x in range(len(bin_lmsg)):
        l_byte = bin(ord(bin_lmsg[x]))[2:]  # generate a binary string of 8 bits for each byte of 32/256.

        while len(l_byte) < 8:  # pad the zero's up to 8
            l_byte = '0' + l_byte

        for y in range(0, 8):
            if l_byte[-1:] == '0':
                verify.append((sha256(signature[z]), pub[z][0]))
                l_byte = l_byte[:-1]
                z += 1
            else:
                verify.append((sha256(signature[z]), pub[z][1]))
                l_byte = l_byte[:-1]
                z += 1

    for p in range(len(verify)):
        if verify[p][0] == verify[p][1]:
            pass
        else:
            return False

    return True

if __name__=="__main__":
    filename = sys.argv[1]
    generateTime=0
    signTime=0
    verifyTime=0
    totalTime=0
    start=time.time()
    with open(filename, "r") as f:
        for line in f:
            message = line
            #print(message)
            #generate key pair
            generate1=time.time()
            priv, pub = random_lkey(numbers=256)
            #print(priv)
            #print(pub)
            generate2=time.time()
            generateTemp=generate2-generate1
            generateTime=generateTime+generateTemp

            #sign message
            sign1=time.time()
            sigature = sign_lkey(priv, message)
            #print(sigature)
            sign2=time.time()
            signTemp=sign2-sign1
            signTime=signTime+signTemp

            #verify signature
            verify1=time.time()
            #print(verify_lkey(sigature, message, pub))
            verify2=time.time()
            verifyTemp=verify2-verify1
            verifyTime=verifyTime+verifyTemp
    end=time.time()
    totalTime=end-start
    #sum=generateTime+signTime+verifyTime
    print("generate key pair time is: ",generateTime)
    print("sign message time is: ",signTime)
    print("verify signature time is: ",verifyTime)
    #print(sum)
    print("total time is: ",totalTime)
