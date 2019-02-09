import logging
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa


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

    # DSA parameters
    key_size = 1024
    param_hash = hashes.SHA256()

    # Refer the follow doc for setting up a specific DSA parameters: DSAParameterNumbers(p, q, g)
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/

    openssl_backend = default_backend()

    # Timing variables
    key_time = 0
    sign_time = 0
    verify_time = 0

    logging.info("Started PyCA DSA with key_size: %s, sha: %s, backend: %s",
                 key_size, str(param_hash.name), str(openssl_backend.name))

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for m in f:
            logging.debug(m)

            start_keygen = time.time()
            # generate a new set of DSA parameters and key in one step
            private_key = dsa.generate_private_key(key_size, openssl_backend)
            public_key = private_key.public_key()
            key_time += time.time() - start_keygen

            start_sign = time.time()
            signature = private_key.sign(m, param_hash)
            sign_time += time.time() - start_sign

            start_verify = time.time()
            try:
                public_key.verify(signature, m, param_hash)
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
