from Utils import *
import argparse
from enum import *
# from enum import Enum, Flag, NAMED_FLAGS, auto


# test_flag: Enum = myTypes.LOCKED | myTypes.MINT
# print (list(test_flag))


# from cryptography.hazmat.primitives.asymmetric.types import (
#     PrivateKeyTypes,
#     PublicKeyTypes,
# )

# if __name__ == main

parser = argparse.ArgumentParser(description="Key generator")
parser.add_argument("--filename", type=str)

args = parser.parse_args()

filename = args.filename
pk_file = filename + ".pk"
pub_file = filename + ".pub"

pk: PrivateKeyTypes  = gen_key()
pub: PublicKeyTypes = pk.public_key()

key_store = key_store(pk)

key_store.save_pk(pk, filename + ".pk")
key_store.save_pub(pub, filename + ".pub")

pk_check = key_store.load_pk(pk_file)
pub_check = key_store.load_pub(pub_file)

print("Private: ",key_store.serialize_pk(pk), key_store.serialize_pk(pk_check))
print("Public: ",key_store.serialize_pub(pub), key_store.serialize_pub(pub_check))