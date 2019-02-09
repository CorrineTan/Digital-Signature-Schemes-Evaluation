import logging
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    """
    pip install cryptography

    OpenSSL backend Python Cryptographic Authority (PyCA)
    https://github.com/pyca
    """

    # INFO or DEBUG
    logging.basicConfig(level=logging.INFO)

    # Input file
    filename = sys.argv[1]

    # EC parameters
    param_curve = ec.SECP256K1()  # bitcoin curve
    param_hash = hashes.SHA256()

    ec_object = ec.ECDSA(param_hash)

    openssl_backend = default_backend()

    # Timing variables
    key_time = 0
    sign_time = 0
    verify_time = 0

    logging.info("Started PyCA ECDSA with curve: %s, sha: %s, backend: %s",
                 str(param_curve.name), str(param_hash.name), str(openssl_backend.name))

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for m in f:
            logging.debug(m)

            start_keygen = time.time()
            private_key = ec.generate_private_key(param_curve, openssl_backend)
            public_key = private_key.public_key()
            key_time += time.time() - start_keygen

            start_sign = time.time()
            signature = private_key.sign(m, ec_object)
            sign_time += time.time() - start_sign

            start_verify = time.time()
            try:
                public_key.verify(signature, m, ec_object)
                logging.debug("Verified: True")
            except InvalidSignature as e:
                logging.warn("InvalidSignature: %s", e.message)
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
