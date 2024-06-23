import argparse
import datetime
import json
import requests
import time
import os
import random

from hashlib import sha256
from flask import Flask, jsonify, request
from uuid import uuid4
from urllib.parse import urlparse

import json
import base64

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

from Utils import *

import logging


#*** TODO: ***
# 1. set up the Pending transaction process
# 2. walk through the transaction condidions
# 3. try to simplify the code ( more sub methods etc )
# 4. add more stuff to the mock stores 
# 5. add datastore for 5 instances ( minimum required for a valid consensus)
#
#
#

class MockDatastore:
    def __init__(self, datastore_path, private_key):
        self.logger = logging.getLogger() 
        self.logger.info('Initializing datastore')
        self.key_store = key_store(private_key)
        self.datastore_path = datastore_path

        with open(datastore_path, 'r') as raw:
            data = json.load(raw)

        self.lib: dict = data['self']
        self.users: dict = data['users']
        self.books: dict = data['books']
        self.nodes: dict = data['nodes']

    def save_datastore(self):
        data = {
            'self': self.lib,
            'users': self.users,
            'books': self.books,
            'nodes': self.nodes
        }
        try:
            with open(self.datastore_path, 'w') as store:
                json.dump(data, store)
        except Exception as e:
            self.logger.error("Exception while saving datastore", e)
            raise

# Trzeba zapobiec kolizjom, jeszcze nvm jak
    def updateBooksStore(self, books: dict):
        # #clear owned books from foreign books list
        # for book in list(books.keys()):
        #     if books[book]['hash'] == self.node_identification_hash:
        #         books.pop(book)

        self.books.update(books)
    

    def getUser(self, hash: str):
        for user in self.users: 
            if user['hash'] == hash: 
                return user
        
        return None

    def get_hash(self)->str:
        return self.lib['hash_address']

# Trzeba zapobiec kolizjom, jeszcze nvm jak
    def add_user(self, users: dict): 
        self.users.update(users)

    def create_book(self, isbn:str, title:str, author:str, uuid:str)->tuple[str,dict]:
        if not self.is_book_unique(uuid): 
            self.logger.error("book is not unique")
            raise Exception("This copy already is on chain")

        book: dict = {
            "isbn": isbn,
            "title": title,
            "author": author,
            "owner": self.get_hash(),
            "uuid": uuid
        }
        
        _, book_hash = self.key_store.hash_it(book)
            
        self.books[book_hash] = book
        return book_hash, book

    def is_book_unique(self, uuid:str)->bool:
        for key in self.books:
            # self.logger.critical(self.books[key]['uuid'])
            if self.books[key]['uuid'] == uuid:
                return False 

        return True

        
class Blockchain(MockDatastore):
    POST_HEADERS = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    def __init__(self, datastore_path, private_key):
        self.logger = logging.getLogger() 
        self.logger.info('Initializing a blockchain')
        super().__init__(datastore_path, private_key)
        self.chain = []
        self.transactions = []
        # self.create_block(proof=1, previous_hash='0')
        self.create_block(previous_hash='0')
        

    # def create_block(self, proof, previous_hash):
    def create_block(self, previous_hash):
        self.logger.debug('creating a block')
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            # 'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        # Clearing transaction list after block is created
        # Each block contains all transactions gathered during last mining period
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    # def proof_of_work(self, previous_proof):
    #     new_proof = 1
    #     check_proof = False
    #     while check_proof is False:
    #         problem = str(pow(new_proof, 2) - pow(int(previous_proof), 2))

    #         hash_operation = self.the_problem(new_proof, previous_proof)
    #         if hash_operation[:4] == '0000':
    #             check_proof = True
    #         else:
    #             new_proof += 1

    #     return new_proof

    # def the_problem(self, new_proof, previous_proof):
    #     return sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()

    def add_node(self, address: str):
        self.logger.debug('Adding new node: ' + address)
        try:
            response = requests.get(f'{address}/chain/get_library_data')
            if response.status_code != 200: 
                raise Exception('errorCode: ' + response.status_code)
        except: 
            self.logger.debug('ERROR: Could not get node data: ' + address)

        lib_data = response.json()['data']
        print (lib_data)

        self.nodes[lib_data['hash_address']] = {
            'lib_mail': lib_data['lib_mail'],
            'lib_name': lib_data['lib_name'], 
            'library_address': lib_data['library_address'],
            'network': lib_data['network'] 
        }
        self.save_datastore()


    def replace_chain(self):
        self.logger.debug('updating chain')
        longest_chain = None
        length_diff = None
        max_length = len(self.chain)
        for node in self.nodes.values():
            node_address = node['network']
            self.logger.debug('updating, node: ' + node_address)
            response = requests.get(f"{node_address}/chain/get_full_chain")
            if response.status_code != 200:
                break
            length = response.json()['length']
            self.logger.debug(max_length)
            self.logger.debug(length)
            chain = response.json()['chain']
            self.logger.debug(chain)
            if length > max_length and self.is_chain_valid(chain):
                self.logger.debug('im shorter')
                length_diff = length - max_length
                max_length = length
                longest_chain = chain

        if longest_chain:
            self.logger.debug('replacing !!! ')
            self.chain = longest_chain
            self._pop_duplicate_pending_transactions(length_diff)
            return True

    def _pop_duplicate_pending_transactions(self, diff:int):
        self.logger.debug(f'removing duplicated pending transactions. diff: {diff}')
        desync_chain = self.chain[-diff:]
        old_tx_list = []
        for block in desync_chain:
            self.logger.debug(block)
            old_tx_list = old_tx_list + block['transactions']
        
        for tx in old_tx_list: self.transactions.remove(tx)


    def find_last_book_transaction(self, book: dict)-> tuple[dict,int]:
        book_hash = book['hash']
        self.logger.debug(f'finding a book: + {book_hash}')
        for block in reversed(self.chain):
            if not block['transactions']: 
                continue 
            for tx in block['transactions']:
                _, bh = self.key_store.hash_it(tx['book'])
                if bh == book_hash: 
                    return tx, block['index'] 

        self.logger.error('Can not find that book' + book_hash)
        raise Exception('Can not find that book anywhere')

# To be fixed - maybe proof is necessary in the end - to randomize who mines the block
    def is_chain_valid(self, chain: list):
        self.logger.debug('checking if chain valid')
        previous_block = chain[0]
        block_index = previous_block['index']
        while block_index < len(chain):
            block = chain[block_index]
            _, previous_block_hash = self.key_store.hash_it(previous_block)
            self.logger.debug('hashe: ' + block['previous_hash'] + ' ' + previous_block_hash)
            if block['previous_hash'] != previous_block_hash:
                self.logger.debug('tu nie działa')
                return False
            # previous_proof = previous_block['proof']
            # proof = block['proof']
            # hash_operation = self.the_problem(proof, previous_proof)
            # print('tu działa')
            # if hash_operation[:4] != '0000':
            #     print('tu nie działa')
            #     return False
            previous_block = block
            block_index += 1

        return True

    # def replace_chain(self):
    #     longest_chain = None
    #     max_length = len(self.chain)
    #     for node in self.nodes:
    #         response = requests.get(f'{self.nodes[node]['network']}/get_chain')
    #         if response.status_code != 200:
    #             break
    #         length = response.json()['length']
    #         chain = response.json()['chain']
    #         if length > max_length and self.is_chain_valid(chain):
    #             max_length = length
    #             longest_chain = chain

    #     if longest_chain:
    #         self.chain = longest_chain
    #         return True


    def validate_transaction(self, tx: dict):
        self.logger.debug('Validating transaction')
        tx_output = tx['output']
        try:
            previous_tx, _ = self.find_last_book_transaction({'hash': self.key_store.hash_it(tx['book'])[1]})
        except Exception as e:
            if tx['type'] != book_status.MINT: raise e
            validator_signature = self.key_store.sign(tx_output, self.key_store.get_priv_key())
            return self.get_hash(), validator_signature

        result = self.validate_book_free_to_access(tx, previous_tx)
        if (result): return result
        result = self.validate_book_not_free_on_chain(tx, previous_tx)
        if (result): return result

        raise Exception('Tx is not valid')


    def validate_book_free_to_access(self, tx: dict, previous_tx: dict):
        self.logger.debug("Checking for free to access")
        is_mint_or_return = lambda x: x['type'] in {book_status.MINT, book_status.RETURN}
        tx_output = tx['output']
        if (is_mint_or_return(previous_tx) and is_mint_or_return(tx)):
            self.logger.error(f'Tx is duplicated ptx: {previous_tx["type"]} ctx: {tx["type"]}')
            raise Exception('Tx is duplicated')

        owner_is_target_of_transaction: bool = tx_output['target_lib_addr'] == tx['book']['owner']
        if (is_mint_or_return(previous_tx) and 
            not previous_tx['locked'] and 
            owner_is_target_of_transaction
        ):
            validator_signature = self.key_store.sign(tx_output, self.key_store.get_priv_key())
            return self.get_hash(), validator_signature
        
        return

    def validate_book_not_free_on_chain(self, tx: dict, previous_tx: dict):
        self.logger.debug("Checking standard validation")
        tx_output = tx['output']
        prev_tx_output = previous_tx['output'] 
        tx_sig: str= tx['input']['use_condition']
        author_key = self.key_store.get_foreign_key(prev_tx_output['target_lib_addr'])
        
        is_signature_valid = self.key_store.verify_signature(tx_output, tx_sig, author_key)
        if (is_signature_valid):
            validator_signature = self.key_store.sign(tx_output, self.key_store.get_priv_key())
            return self.get_hash(), validator_signature

        return


    def select_validators(self, number_of_validators: int) -> list:
        self.logger.debug('Selecting validators')
        potential_validators = random.sample(list(self.nodes.values()), k=number_of_validators)
        validators = []
        for node in potential_validators: 
            node_address = node['network']
            try: 
                response = requests.get(f"{node_address}/isalive")
                if response.status_code == 200:
                    validators.append(node['network'])
            except Exception as e: 
                continue

        self.logger.debug('Selected those: ' + str(validators))
        return validators 

    def reach_consensus(self, tx: dict)-> list:
        self.logger.debug('reaching consensus')

        number_of_validators = 2
        validators = self.select_validators(number_of_validators)
        self.logger.debug(validators)
        consensus = [] 
        self.logger.debug('VALIDATORS:')
        for validator in validators:
            self.logger.debug(validator)
            try:
                response = requests.post(f'{validator}/chain/validate_transaction', json=tx, headers=self.POST_HEADERS)
                if response.status_code != 200:
                    self.logger.info(response)
                    continue
            except:
                self.logger.error("Error while validating: ", response)
                continue

            content = response.json()
            self.logger.debug('content: ' + str(content))
            consensus.append([content['validator'], content['validator_sig']])
            
            
        is_byzantine_secured = len(consensus) > number_of_validators*(2/3)
        if is_byzantine_secured: 
            return consensus

        raise Exception('Consensus not reached')

    def _hash_list(self, l:list)->list:
        result = []
        for i in l: 
            result.append(self.key_store.hash_it(i))
        return result

    def update_pending_transactions(self, transactions:list)->tuple[int,list]:
        self.logger.debug('updating pending transactions')

        hash_list = lambda x: [self.key_store.hash_it(a)[1] for a in x]
        incoming = hash_list(transactions) 
        pending = hash_list(self.transactions)
        missing_from_pending = [i for i in incoming if i not in pending]
        
        for tx in transactions: 
            if self.key_store.hash_it(tx)[1] in missing_from_pending: self.transactions.append(tx)
        # self.transactions.append(
        #     tx for tx in transactions if self.key_store.hash_it(tx)[1] in missing_from_pending
        # )

        return self.get_previous_block()['index'] + 1, self.transactions

    def propagate_transactions(self, transactions:list)->list: 
        self.logger.debug('Propagating transaction on chain') 
        propagated = []
        for node in self.nodes.values():
            node_address = node['network']
            self.logger.debug(node_address)
            try:
                response = requests.post(f'{node_address}/chain/sync_tx', json=transactions, headers=self.POST_HEADERS)
                self.logger.info(f'Transactions propagated to: {node_address}')
                self.logger.info(f'RESPONSE: {response}')
            except Exception as e:
                self.logger.error(f'Node {node_address} is unreachable')
                # self.logger.error(f"Node {node_address} is unreachable", e)
                continue
            propagated.append(node_address)

        return propagated
        # if tx confirmed
        #     send tx to known nodes 
        #     include info about which block should it be in

    def propagate_chain(self) -> tuple[bool, list]:
        self.logger.debug('Propagating chain after mining')
        propagated = []
        for node in self.nodes.values():
            node_address = node['network']
            try: 
                response = requests.get(f"{node_address}/chain/replace")
                if (not str(response.status_code).startswith('2')): continue
                print(node_address)
                propagated.append(node_address)
            except Exception as e:
                self.logger.error('Exception', e)
                raise e

        return (True, propagated) if len(propagated) >0 else (False, propagated) 
         
    def add_valid_transaction(self): return
        # check if consensus reached
        # check if target block is current block
        # if yes: 
        #     add transaction
        #     return positive
        # if no:
        #     replace_chain
        #     add transaction
        #     return positive
        # return negative

## --- Book operations
    # TODO: hash_id z pub_key - done
    # TODO: fix up mint tx - done 
    # TODO: add logger - kinda
    # TODO: Test reserve tx - fixed
    # TODO: Fix up duplicate tx-es in the pending transactions 
    # TODO: Test rent tx - done
    # TODO: Test return tx - done
    # TODO: Test kill tx - done
    # TODO: Test :mint -> reserve -> reserve -> rent -> reserve -> rent -> kill -> return -> rent -> return - done
    # TODO: implement 3 way mechanism
    # TODO: add propagation and validation mechanism
    # TODO: add consensus mechanism


    def _is_not_target_of_previous_tx(self, tx: dict)->bool: 
        return tx is None or not tx['output']['target_lib_addr'] == self.get_hash() 

    def _is_tx_mint_or_return(self, tx: dict)-> bool:
        return tx['type'] in {book_status.MINT, book_status.RETURN}
        
    def _is_tx_reserved_but_overdue(self, tx:dict)-> bool:
        return tx['type'] == book_status.RESERVE and tx['output']['end_date'] > datetime.datetime.now().timestamp()

    def _add_tx_to_pending(self, tx: dict): 
        pending_hashes = [self.key_store.hash_it(p['book'])[1] for p in self.transactions]
        if self.key_store.hash_it(tx['book'])[1] in pending_hashes: 
            raise Exception("Duplicate pending transaction")
        
        self.transactions.append(tx)

    def add_mint_transaction(self, type: int, book: dict) -> int:
        self.logger.debug('Adding mint transaction')

        try:
            if type != book_status.MINT: 
                raise Exception('To mint a book type must be set to 0')

            new_book_hash, new_book = self.create_book(book['isbn'], book['title'], book['author'], book['uuid'])
        except Exception as e:
            self.logger.error('cannot create given book', e)
            raise

        try: 
            output_data = {
                'target_lib_addr': self.get_hash(),
                'user_hash': None,
                'end_date': None
            }
            transaction = {
                'type': type,
                'timestamp': str(datetime.datetime.now()),
                'input': None,
                'output': output_data, 
                'book': new_book,
                'locked': False,
                'author': self.get_hash(),
                'validators': []

            }

            try: 
                transaction['validators'] = self.reach_consensus(transaction)
                if not self.propagate_transactions([transaction]):
                    raise Exception("All nodes are unresponsive - rejecting tx")
            except Exception as e:
                self.logger.error('Exception ', e.args)
                raise Exception('Transaction declined', e)
            
            # self.transactions.append(transaction)
            self._add_tx_to_pending(transaction)
        except Exception as e:
            self.books.pop(new_book_hash)
            self.logger.error('Could not add mint transaction', e)
            raise Exception('could not add the transaction', e)


        # self.save_datastore()
        return self.get_previous_block()['index'] + 1, self.transactions

    def add_reserve_transaction(self, type: int, book: dict, output: dict):
        self.logger.debug('Adding reserve transaction')
        previous_book_tx, _ = self.find_last_book_transaction(book)        
        self.reserve_initial_checks(previous_book_tx)

        date_now = datetime.datetime.now()
        date_target = date_now + datetime.timedelta(days=output['days'])

        _, hashed_prev_book_tx = self.key_store.hash_it(previous_book_tx)

        output_data = {
            'target_lib_addr': output['target_lib_addr'],
            'user_hash': output['user_hash'],
            'end_date': date_target.timestamp()
        }
        input_data = {
            'prev_tx': hashed_prev_book_tx,
            'use_condition': self.key_store.sign(output_data, self.key_store.get_priv_key()) 
        }
        transaction = {
            'type': type,
            'timestamp': date_now.timestamp(),
            'input': input_data,
            'output': output_data, 
            'book': previous_book_tx['book'],
            'locked': False,
            'author': self.get_hash(),
            'validators': []
        }

        self.reserve_finalize_tx(transaction)
        self._add_tx_to_pending(transaction)
        return self.get_previous_block()['index'] + 1, self.transactions

    def reserve_initial_checks(self, previous_book_tx: dict):
        if (previous_book_tx['locked'] and not previous_book_tx['book']['owner'] == self.get_hash()):
            raise Exception('Wrong address: this node is not currently allowed to manage requested book.')

        if (
            not self._is_tx_mint_or_return(previous_book_tx) or 
            self._is_tx_reserved_but_overdue(previous_book_tx) 
        ):
            raise Exception('Book is not free yet')

    def reserve_finalize_tx(self, transaction: dict):
        try: 
            transaction['validators'] = self.reach_consensus(transaction)
            if not self.propagate_transactions([transaction]):
                raise Exception("All nodes are unresponsive - rejecting tx")
        except Exception as e:
            self.logger.error('Exception ', e.args)
            raise Exception('Transaction declined', e)


    def add_rent_transaction(self, type: int, book: dict, output: dict): 
        self.logger.debug('Adding rent transaction')
        previous_book_tx, _ = self.find_last_book_transaction(book)        
        
        if (
            self._is_not_target_of_previous_tx(previous_book_tx) 
        ):
            self.logger.error('Wrong address: this node is not currently allowed to manage requested book')
            raise Exception('Wrong address: this node is not currently allowed to manage requested book')

# TODO: Simplify this one: its confusing
        self.logger.debug("logic checks")
        while (
            self._is_tx_mint_or_return(previous_book_tx) or 
            self._is_tx_reserved_but_overdue(previous_book_tx)
            # (
            #     previous_book_tx['type'] == book_status.RESERVE and 
            #     previous_book_tx['output']['end_date'] > datetime.datetime.now().timestamp()
            # )
        ):
            if (
                previous_book_tx['type'] == book_status.RESERVE and 
                previous_book_tx['output']['user_hash'] == output['user_hash']
                ): break 

            raise Exception('Book is not free yet')


        date_now = datetime.datetime.now()
        date_target = date_now + datetime.timedelta(days=output['days'])
        
        _, hashed_prev_book_tx = self.key_store.hash_it(previous_book_tx)

        self.logger.debug("preparing tx")
        output_data = {
            'target_lib_addr': output['target_lib_addr'] if previous_book_tx['type'] != book_status.RESERVE else previous_book_tx['author'],
            'user_hash': output['user_hash'],
            'end_date': date_target.timestamp()
        }
        input_data = {
            'prev_tx': hashed_prev_book_tx,
            'use_condition': self.key_store.sign(output_data, self.key_store.get_priv_key()) 
        }
        transaction = {
            'type': type,
            'timestamp': date_now.timestamp(),
            'input': input_data,
            'output': output_data, 
            'book': previous_book_tx['book'],
            'locked': False,
            'author': self.get_hash(),
            'validators': []
        }
        
        try: 
            
            transaction['validators'] = self.reach_consensus(transaction)
            if not self.propagate_transactions([transaction]):
                self.logger.error("All nodes are unresponsive - rejecting tx")
                raise Exception("All nodes are unresponsive - rejecting tx")
        except Exception as e:
            self.logger.error('Exception ', e.args)
            raise Exception('Transaction declined', e)
            
        # self.propagate_and_validate_tx()
        self._add_tx_to_pending(transaction)
        return self.get_previous_block()['index'] + 1, self.transactions

    def add_pending_return_transaction(self, type: int, book: dict, output: dict):
        self.logger.debug('Adding  transaction')
        previous_book_tx, _ = self.find_last_book_transaction(book)        


        if (self._is_not_target_of_previous_tx(previous_book_tx)):
            # self.logger.debug('Target address: ' + previous_book_tx['output']['target_lib_addr'] + '\nMy address: ' + self.lib['hash_id'])
            raise Exception('Wrong address: this node is not currently allowed to manage requested book.')

        self.logger.info(previous_book_tx['type'])
        self.logger.info(f'{book_status.MINT} {book_status.RETURN}')

        previous_transaction_is_rent = previous_book_tx['type'] in {book_status.RENT}

        if (not previous_transaction_is_rent):
            raise Exception('Book was not yet rented')

        date_now = datetime.datetime.now()
        date_target = date_now + datetime.timedelta(days=output['days'])

        _, hashed_prev_book_tx = self.key_store.hash_it(previous_book_tx)

        output_data = {
            'target_lib_addr': output['target_lib_addr'],
            'user_hash': output['user_hash'],
            'end_date': date_target.timestamp()
        }
        input_data = {
            'prev_tx': hashed_prev_book_tx,
            'use_condition': self.key_store.sign(output_data, self.key_store.get_priv_key()) 
        }
        transaction = {
            'type': type,
            'timestamp': date_now.timestamp(),
            'input': input_data,
            'output': output_data, 
            'book': previous_book_tx['book'],
            'locked': False,
            'author': self.get_hash(),
            'validators': []
        }

        try: 
            transaction['validators'] = self.reach_consensus(transaction)
            if not self.propagate_transactions([transaction]):
                raise Exception("All nodes are unresponsive - rejecting tx")
        except Exception as e:
            self.logger.error('Exception ', e.args)
            raise Exception('Transaction declined', e)

        self._add_tx_to_pending(transaction)

        return self.get_previous_block()['index'] + 1, self.transactions

    def add_return_transaction(self, type: int, book: dict):
        previous_book_tx, _ = self.find_last_book_transaction(book)        

        CURRENT_LIB_IS_OWNER_AND_TARGET_OF_PREVIOUS = previous_book_tx['output']['target_lib_addr'] == self.get_hash() and self.get_hash() == previous_book_tx['book']['owner']
        if (
            previous_book_tx is None or not CURRENT_LIB_IS_OWNER_AND_TARGET_OF_PREVIOUS
        ):
            raise Exception('Wrong address: this node is not currently allowed to manage requested book')

        if (previous_book_tx['type'] not in {book_status.RESERVE, book_status.PENDING, book_status.EXCHANGE}):
            raise Exception('Was is not currently rented/reserved/three-way-exchanged')

        date_now = datetime.datetime.now()
        
        _, hashed_prev_book_tx = self.key_store.hash_it(previous_book_tx)

        output_data = {
            'target_lib_addr': self.get_hash(),
            'user_hash': None,
            'end_date': None 
        }
        input_data = {
            'prev_tx': hashed_prev_book_tx,
            'use_condition': self.key_store.sign(output_data, self.key_store.get_priv_key()) 
        }
        transaction = {
            'type': type,
            'timestamp': date_now.timestamp(),
            'input': input_data,
            'output': output_data, 
            'book': previous_book_tx['book'],
            'locked': False,
            'author': self.get_hash(),
            'validators': []
 
        }

        try: 
            transaction['validators'] = self.reach_consensus(transaction)
            if not self.propagate_transactions([transaction]):
                raise Exception("All nodes are unresponsive - rejecting tx")
        except Exception as e:
            self.logger.error('Exception ', e.args)
            raise Exception('Transaction declined', e)
        
        self._add_tx_to_pending(transaction)
        # self.propagate_and_validate_tx()
        return self.get_previous_block()['index'] + 1, self.transactions

    def add_destroy_transaction(self, type: int, book: dict):
        previous_book_tx, _ = self.find_last_book_transaction(book)        
        if (
            previous_book_tx is None or 
            previous_book_tx['output']['target_lib_addr'] != self.get_hash() 
        ):
            raise Exception('Wrong address: this node is not currently allowed to manage requested book')

        if (
            not self._is_tx_mint_or_return(previous_book_tx)
            # previous_book_tx['type'] not in {0,3}
        ):
            raise Exception('Was not yet returned - cannot burn if book is still with the user')

        date_now = datetime.datetime.now()
        output_data = {
            'target_lib_addr': '0x00000000000000000000000000000000x0',
            'user_hash': 'da book es ded now beltalowda',
            'end_date': None 
        }
        self.logger.critical('hashed tx', self.key_store.hash_it(previous_book_tx))
        input_data = {
            'prev_tx': self.key_store.hash_it(previous_book_tx)[1],
            'use_condition': self.key_store.sign(output_data, self.key_store.get_priv_key()) 
        }
        transaction = {
            'type': 4,
            'timestamp': date_now.timestamp(),
            'input': input_data,
            'output': output_data, 
            'book': previous_book_tx['book'],
            'locked': True,
            'author': self.get_hash(),
            'validators': []
        }

        try: 
            transaction['validators'] = self.reach_consensus(transaction)
            if not self.propagate_transactions([transaction]):
                raise Exception("All nodes are unresponsive - rejecting tx")
        except Exception as e:
            self.logger.error('Exception ', e.args)
            raise Exception('Transaction declined', e)
        
        self._add_tx_to_pending(transaction)
        # self.propagate_and_validate_tx()
        return self.get_previous_block()['index'] + 1, self.transactions

    def add_three_way_transaction(self): return

## --- Diagnostic and tests
    def diagnostics(self):
        # self.get_hash()
        _, self.lib['hash_address'] = self.key_store.hash_bytes(self.key_store.serialize_pub(self.key_store.get_pub_key()))
        self.save_datastore()

        # print('Books: ', hash_it(self.books))
        # print('Users: ', hash_it(self.users))
        # print('Test: ', hash_it('hello'))
        # print('Books: ', hash_it(self.books))
        # h_bytes, h_str = hash_it(self.books)
        # if (str_to_byte(h_str) == h_bytes): print('working good ', h_bytes, str_to_byte(h_str))
        # # hash_string = base64.urlsafe_b64encode(hash_bytes).decode('utf-8')
        # signature = sign(self.books, self.private_key)
        # signature_2 = sign(self.users, self.private_key)
        # pub_key_2 = load_pub('./node_1/ecdsa.pub')
        # pem_pub = serialize_pub(self.public_key)
        # print('pub: ', pem_pub)
        # print('pub elem: ', pem_pub.splitlines()[1], pem_pub.splitlines()[2])
        # print('Sig: ', signature)
        # print(verify_signature(self.books, signature, pub_key_2))

        # print('Date',type(datetime.datetime.now().timestamp()), datetime.datetime.now() + datetime.timedelta(days=10))
        return
