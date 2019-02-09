import hashlib
import logging
import sys
import time

import nacl.encoding
import nacl.signing
from nacl.exceptions import BadSignatureError


def main():
    """
    pip install pynacl

    Documentation
    https://pynacl.readthedocs.io/en/stable/signing/

    Python binding to the Networking and Cryptography (NaCl) library by PyCA
    https://github.com/pyca/pynacl

    Python Cryptographic Authority (PyCA)
    https://github.com/pyca
    """

    # INFO or DEBUG
    logging.basicConfig(level=logging.INFO)

    # Input file
    filename = sys.argv[1]

    # Utils
    param_hash = hashlib.sha256
    param_encoder = nacl.encoding.HexEncoder

    # Timing variables
    key_time = 0
    sign_time = 0
    verify_time = 0

    logging.info("Started PyCA PyNaCl Ed25519")

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for m in f:
            logging.debug(m)

            start_keygen = time.time()
            private_key = nacl.signing.SigningKey.generate()
            public_key = private_key.verify_key
            key_time += time.time() - start_keygen

            logging.debug("public_key: %s", public_key.encode(encoder=param_encoder))

            # This may not be required as message will be hashed sha512 during sign() process.
            # Unless we deliberately want to hash the message.
            # Look at:  https://pynacl.readthedocs.io/en/stable/_images/ed25519.png
            # m = param_hash(m.encode()).hexdigest()
            # logging.debug("param_hash m: %s", m)

            start_sign = time.time()
            # signed data type is nacl.signing.SignedMessage
            signed = private_key.sign(m)
            sign_time += time.time() - start_sign

            # logging.debug("message: %s, binary_signature: %s", signed.message, signed.signature)

            start_verify = time.time()
            try:
                public_key.verify(signed.message, signed.signature)
                logging.debug("Verified: True")
            except BadSignatureError as e:
                logging.warn("BadSignatureError: %s", e.message)
                exit(1)
            verify_time += time.time() - start_verify

    sum_time = key_time + sign_time + verify_time

    logging.info("Total time cost for generating key is: " + str(key_time) + " s")
    logging.info("Total time cost for signing the message is: " + str(sign_time) + " s")
    logging.info("Total time cost for verifying the message is: " + str(verify_time) + " s")
    logging.info("Total time cost for key generating, message signing and verifying: " + str(sum_time) + " s")
    logging.info("Total time cost for system time: " + str(time.time() - start) + " s")


if __name__ == "__main__":
    main()
