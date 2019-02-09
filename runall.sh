#!/usr/bin/env bash

[ $# -eq 0 ] && { echo "Usage:   bash $0 titanic.csv"; exit 1; }

DATA_SET=$1

echo "Running Lamport..."
time python Lamport.py ${DATA_SET}
echo ""

echo "Running ecdsa_fast..."
time python ecdsa_fast.py ${DATA_SET}
echo ""

echo "Running ecdsa_pyca..."
time python ecdsa_pyca.py ${DATA_SET}
echo ""

echo "Running eddsa_25519..."
time python eddsa_25519.py ${DATA_SET}
echo ""

echo "Running eddsa_pynacl..."
time python eddsa_pynacl.py ${DATA_SET}
echo ""

echo "Running eddsa_libnacl..."
time python eddsa_libnacl.py ${DATA_SET}
echo ""

echo "Running rsa_pyca..."
time python rsa_pyca.py ${DATA_SET}
echo ""

echo "Running dsa_pyca..."
time python dsa_pyca.py ${DATA_SET}
echo ""

# Slower than RSA, so commented out for now :(
#echo "Running ecdsa_process..."
#time python ecdsa_process.py ${DATA_SET}
#echo ""

echo Done
