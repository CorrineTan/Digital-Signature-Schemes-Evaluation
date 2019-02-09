import hashlib
import logging
import sys
import time

import ed25519


def main():
    """
    pip install ed25519

    Documentation
    https://github.com/warner/python-ed25519
    https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/

    NOTE: clean up version of eddsa_25519.py
    """

    # INFO or DEBUG
    logging.basicConfig(level=logging.INFO)

    filename = sys.argv[1]

    param_hash = hashlib.sha256

    time1 = 0
    time2 = 0
    time3 = 0

    with open(filename, "r") as f:
        # skip file reading time as well
        start = time.time()

        for line in f:

            # This may not be required as message will be hashed sha512 during sign() process.
            # Unless we deliberately want to hash the message.
            # Look at:
            #   http://ffp4g1ylyit3jdyti1hqcvtb-wpengine.netdna-ssl.com/warner/files/2011/11/key-formats.png
            #
            # line = param_hash(line.encode()).hexdigest()
            # logging.debug("hash message: %s", line)

            start_keygen = time.time()
            signing_key, verifying_key = ed25519.create_keypair()
            time1 += time.time() - start_keygen

            start_sign = time.time()
            signature = signing_key.sign(line)
            time2 += time.time() - start_sign

            start_verify = time.time()
            try:
                verifying_key.verify(signature, line)
                logging.debug("Signature is good!")
            except ed25519.BadSignatureError as e:
                logging.warn("BadSignatureError: %s", e.message)
                exit(1)
            time3 += time.time() - start_verify

    sum_time = time1 + time2 + time3

    logging.info("The time used to generate key pairs: %s", time1)
    logging.info("The time used to sign messages: %s", time2)
    logging.info("The time used to verify messages: %s", time3)
    logging.info("Total time cost for key generating, message signing and verifying: %s", sum_time)
    logging.info("Total time cost for system time: %s", str(time.time() - start))


if __name__ == '__main__':
    main()
