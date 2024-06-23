import os
import json
import base64
import argparse

from hashlib import sha256
from flask import Flask, jsonify, request
from uuid import uuid4
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from enum import IntEnum

class book_status(IntEnum):
    MINT = 0
    RESERVE = 1
    RENT = 2 
    PENDING = 3
    RETURN = 4 
    DELETE = 5
    EXCHANGE = 6


# book: IntEnum = book_status(3)


# class transaction:




def gen_key() -> PrivateKeyTypes:
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    ) 
    return private_key

def save_pk(pk: PrivateKeyTypes, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def save_pub(pub: PublicKeyTypes, filename):
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(pem)
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_pk(filename) -> PrivateKeyTypes:
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, password=None)
    return private_key

def load_pub(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines)
    return public_key 

global_hash = hashes.SHA512()

class key_store:
    def __init__(self, private_key):
        self.private_key: PrivateKeyTypes = load_pk(private_key)
        self.foreign_keys: list[PublicKeyTypes] = []
        self.load_foreign_public_keys()


    def get_foreign_key(self, hash: str) -> PublicKeyTypes:
        for fk in self.foreign_keys:
            _, serialized = self.hash_bytes(self.serialize_pub(fk))
            if hash == serialized:
                return fk

        raise Exception("Could not find matching public key") 

    def load_foreign_public_keys(self): 
        directory = os.path.dirname(os.path.abspath(__file__))
    
        for file in os.listdir(directory):
            filename = os.fsdecode(file)
            file_path = os.path.join(directory, filename) 

            if not (filename.startswith("node") and os.path.isdir(file_path)):
                continue

            key_path = file_path + "\ecdsa.pub"
            pub = load_pub(key_path)

            if self.serialize_pub(self.get_pub_key()) == self.serialize_pub(pub):
                continue

            print(key_path)
            self.foreign_keys.append(pub)

        print(self.foreign_keys)
        return


    def serialize_pk(self, pk: PrivateKeyTypes) -> str:
        pem = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem


    def serialize_pub(self, pub: PublicKeyTypes) -> str:
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem

    # def hash(data):
    #     encoded_block = json.dumps(data, sort_keys=True).encode()
    #     return sha256(encoded_block).hexdigest()

    def hash_it(self, data):
        encoded_data = json.dumps(data, sort_keys=True).encode("utf-8")
        digest = hashes.Hash(global_hash)
        digest.update(bytes(encoded_data))
        hash_bytes = digest.finalize()
        hash_string = base64.urlsafe_b64encode(hash_bytes).decode("utf-8")
        return hash_bytes, hash_string

    def hash_bytes(self, data):
        self.byte_to_str(data)
        digest = hashes.Hash(global_hash)
        digest.update(bytes(data))
        hash_bytes = digest.finalize()
        hash_string = base64.urlsafe_b64encode(hash_bytes).decode("utf-8")
        return hash_bytes, hash_string

    def str_to_byte(self, h: str):
        return base64.urlsafe_b64decode(h.encode("utf-8"))

    def byte_to_str(self, b): 
        return base64.urlsafe_b64encode(b).decode("utf-8")

    # data
    def sign(self, data, key: PrivateKeyTypes):
        digest, s  = self.hash_it(data)
        sig = key.sign(
            digest, 
            ec.ECDSA(utils.Prehashed(global_hash))
        )
        return base64.urlsafe_b64encode(sig).decode("utf-8") 
        

    def verify_signature(self, data, sig, key: PublicKeyTypes):
        digest, s = self.hash_it(data)
        try:
            key.verify(
                base64.urlsafe_b64decode(sig.encode("utf-8")),
                digest, 
                ec.ECDSA(utils.Prehashed(global_hash))
            )
        except:
            # print(e.args)
            return False 
        return True

    def get_priv_key(self): return self.private_key

    def get_pub_key(self) -> PublicKeyTypes:
        return self.private_key.public_key()


if __name__ == "__main__": 

    parser = argparse.ArgumentParser(description="Key generator")
    parser.add_argument("--filename", type=str)

    args = parser.parse_args()

    filename = args.filename
    pk_file = filename + ".pk"
    pub_file = filename + ".pub"
    print(filename)

    pk: PrivateKeyTypes  = gen_key()
    pub: PublicKeyTypes = pk.public_key()

    save_pk(pk, filename + ".pk")
    save_pub(pub, filename + ".pub")

    key_store = key_store(pk_file)


    pk_check = load_pk(pk_file)
    pub_check = load_pub(pub_file)

    print("Private: ",key_store.serialize_pk(pk), key_store.serialize_pk(pk_check))
    print("Public: ",key_store.serialize_pub(pub), key_store.serialize_pub(pub_check))