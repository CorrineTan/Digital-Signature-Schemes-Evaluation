import hashlib
import logging
import sys
import time

from fastecdsa import curve, keys, ecdsa


def main():
    """
    pip install fastecdsa

    Refer following links for more curves and parameters
        - https://pypi.org/project/fastecdsa/
        - https://pypi.org/project/fastecdsa/
        - https://github.com/AntonKueltz/fastecdsa
    """

    # INFO or DEBUG
    logging.basicConfig(level=logging.INFO)

    # Input file
    filename = sys.argv[1]

    # EC parameters
    param_curve = curve.secp256k1  # bitcoin curve
    param_hash = hashlib.sha256

    # Timing variables
    key_time = 0
    sign_time = 0
    verify_time = 0

    logging.info("Started Fast ECDSA with curve: %s, sha: %s", param_curve, str(param_hash.__name__))

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for m in f:
            logging.debug(m)

            # This is no longer required as message will be hashed during ecdsa.sign()
            # m = hashlib.sha256(m.encode()).hexdigest()
            # logging.debug(m)

            start_keygen = time.time()
            private_key, public_key = keys.gen_keypair(param_curve)
            key_time += time.time() - start_keygen

            start_sign = time.time()
            r, s = ecdsa.sign(m, private_key, curve=param_curve, hashfunc=param_hash)
            sign_time += time.time() - start_sign

            start_verify = time.time()
            valid = ecdsa.verify((r, s), m, public_key, curve=param_curve, hashfunc=param_hash)
            logging.debug("Verified: %s" % valid)
            verify_time += time.time() - start_verify

    sum_time = key_time + sign_time + verify_time

    logging.info("Total time cost for generating key is: " + str(key_time) + " s")
    logging.info("Total time cost for signing the message is: " + str(sign_time) + " s")
    logging.info("Total time cost for verifying the message is: " + str(verify_time) + " s")
    logging.info("Total time cost for key generating, message signing and verifying: " + str(sum_time) + " s")
    logging.info("Total time cost for system time: " + str(time.time() - start) + " s")


if __name__ == "__main__":
    main()
