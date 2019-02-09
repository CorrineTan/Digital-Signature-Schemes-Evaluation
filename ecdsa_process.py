# Created by Tenglun Tan 09/28/2018.

import ecdsa
import hashlib
from binascii import hexlify, unhexlify
import time
import os
from ecdsa import NIST384p, SigningKey
from ecdsa.util import randrange_from_seed__trytryagain


def gen_private_key(n=32):
    private_key = hexlify(os.urandom(n)).decode('ascii')
    return private_key


def message_sha256(n):
    message = hashlib.sha256(n.encode()).digest()
    return message


def secure_gen_private_key(seed):
    secexp = randrange_from_seed__trytryagain(seed, NIST384p.order)
    return SigningKey.from_secret_exponent(secexp, curve=NIST384p)


def gen_vk_sk(private_key):
    secret = unhexlify(private_key)
    sk = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    verifying_key = hexlify(vk.to_string()).decode()  # if we want to print the readable key
    return vk, sk


def gen_public_key(vk):
    order = ecdsa.SECP256k1.generator.order()   # ecp256k1 is the Bitcoin elliptic curve
    p = vk.pubkey.point
    x_str = ecdsa.util.number_to_string(p.x(), order)
    y_str = ecdsa.util.number_to_string(p.y(), order)
    public_key_compressed = hexlify(bytes(chr(2 + (p.y() & 1)), 'ascii') + x_str).decode('ascii')
    public_key_uncompressed = hexlify(bytes(chr(4), 'ascii') + x_str + y_str).decode('ascii')
    return public_key_compressed


def sign_msg(msg, sk):
    signed_msg = sk.sign(msg)
    return signed_msg


def verify_msg(msg, signed_msg, vk):
    try:
        assert vk.verify(signed_msg, msg)
        print("Verified True")
    except AssertionError:
        print ("Verified False")
    except ecdsa.keys.BadSignatureError:
        print ("Bad Signature")


if __name__ == "__main__":
    open_file = "titanic.csv"
    generate_time_sum = 0
    sign_time_sum = 0
    verify_time_sum = 0
    time_sum = 0
    start_time = time.time()
    with open(open_file, "r") as f:
        for line in f:
            message = line
            #message = "Our team is just awesome. Shh...It's a secret!"

            message_now = message_sha256(message)

            # generate key section:
            generate_start = time.time()
            private_key = gen_private_key(n=32)
            vk, sk = gen_vk_sk(private_key)
            #verify_key = hexlify(vk.to_string()).decode()
            #sign_key = hexlify(sk.to_string()).decode()
            # public_key = gen_public_key(vk)
            # generate a more secure key
            # seed = os.urandom(NIST384p.baselen)
            # sk1a = secure_gen_private_key(seed)
            # sk1b = secure_gen_private_key(seed)
            # sk2 = secure_gen_private_key("2-" + seed)
            generate_end = time.time()
            #print("My private key is: " + private_key)
            #print("My verify key is: " + verify_key)
            #print("My signing key is: " + sign_key)
            #print("My public key is: " + public_key)
            generate_time = generate_end - generate_start
            generate_time_sum += generate_time
            #print("Time for generateing key is: " + str(generate_time) + " s")

            # sign the message:
            sign_start = time.time()
            signed_msg = sign_msg(message_now, sk)
            sign_end = time.time()
            signed_message = hexlify(signed_msg)
            sign_time = sign_end - sign_start
            sign_time_sum += sign_time
            #print("My signed message is: " + str(signed_message))
            #print("Time for signing the message is: " + str(sign_time) + " s")

            # verify the message:
            verify_start = time.time()
            verify_msg(message_now, signed_msg, vk)
            verify_end = time.time()
            verify_time = verify_end - verify_start
            verify_time_sum += verify_time
            #print("Time for verifing the message is: " + str(verify_time) + " s")
    end_time = time.time()
    system_time = end_time - start_time
    sum_time = generate_time_sum + sign_time_sum + verify_time_sum
    print("Total time cost for generateing key is: " + str(generate_time_sum) + " s")
    print("Total time cost for signing the message is: " + str(sign_time_sum) + " s")
    print("Total time cost for verifying the message is: " + str(verify_time_sum) + " s")
    print("Total time cost for key generating, message signing and verifying: " + str(sum_time) + " s")
    print("Total time cost for system time: " + str(system_time) + " s")
