import logging
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


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

    # RSA parameters
    public_exponent = 65537
    key_size = 2048
    param_hash = hashes.SHA256()

    rsa_padding = padding.PSS(mgf=padding.MGF1(param_hash), salt_length=padding.PSS.MAX_LENGTH)

    openssl_backend = default_backend()

    # Timing variables
    key_time = 0
    sign_time = 0
    verify_time = 0

    logging.info("Started PyCA RSA with public_exponent: %s, key_size: %s, rsa_padding: %s, sha: %s, backend: %s",
                 public_exponent, key_size, str(rsa_padding.name), str(param_hash.name), str(openssl_backend.name))

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for m in f:
            logging.debug(m)

            start_keygen = time.time()
            private_key = rsa.generate_private_key(public_exponent, key_size, openssl_backend)
            public_key = private_key.public_key()
            key_time += time.time() - start_keygen

            start_sign = time.time()
            signature = private_key.sign(m, rsa_padding, param_hash)
            sign_time += time.time() - start_sign

            start_verify = time.time()
            try:
                public_key.verify(signature, m, rsa_padding, param_hash)
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
