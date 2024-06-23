import argparse
from logging.config import dictConfig

from hashlib import sha256
from flask import Flask, jsonify, request
from uuid import uuid4
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from Utils import *
from Blockchain import *

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

parser = argparse.ArgumentParser(description='Generic Library Node')
parser.add_argument('--port', type=int)
# parser.add_argument('--data', type=str)
# parser.add_argument('--key', type=str)
parser.add_argument('--node', type=int)
args = parser.parse_args()

node_port = args.port
# data_path = args.data
# rsa_private_key_path = args.key
data_path = './node_' + str(args.node) + '/node_data.json'
rsa_private_key_path = './node_' + str(args.node) + '/ecdsa.pk'


app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

blockchain = Blockchain(data_path, rsa_private_key_path)
blockchain.diagnostics()

# Create address for the node on Port
node_address = str(uuid4()).replace('-', '')

# health check
@app.route('/isalive/', methods=['GET'])
def is_node_alive():

    response = {
        'message': 'Im alive',
    }

    return jsonify(response), 200

## --- Basic node requests
# get node info


# get books from datastore

# get registered users

# add a user

# add a node 

## --- Blockchain requests 
# show chain
@app.route('/chain/get_full_chain', methods=['GET'])
def get_chain_request():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/chain/get_pending', methods=['GET'])
def get_pending_transactions():
    response = {
        'pending transactions': blockchain.transactions,
    }
    return jsonify(response), 200

# mine block 
@app.route('/chain/mine_block', methods=['GET'])
def mine_block_request():
    chain_replaced = blockchain.replace_chain()

    previous_block = blockchain.get_previous_block()
    # previous_proof = previous_block['proof']
    # proof = blockchain.proof_of_work(previous_proof)
    _, previous_hash = blockchain.key_store.hash_it(previous_block)
     
    if len(blockchain.transactions) == 0: 
        return 'There are no new transactions to mine', 400

    # block = blockchain.create_block(proof, previous_hash)
    block = blockchain.create_block(previous_hash)
    response = {
        'message': 'Congrats: mining successful',
        'replaced_before_mining': chain_replaced,
        'index': block['index'],
        'timestamp': block['timestamp'],
        # 'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions']
    }

    try: 
        success, propagated_nodes = blockchain.propagate_chain()
        if not success: response['message'] = 'Mining successfull but could not propagate the chain'
        response['notified nodes'] = propagated_nodes
    except Exception as e:
        response['message'] = 'Exception during block propagation but block was mined'
        response['error'] = e.args
        raise e
        return jsonify(response), 400

    return jsonify(response), 200

@app.route('/chain/replace/', methods=['GET'])
def replace_chain_request():
    try:
        chain_replaced = blockchain.replace_chain()
    except Exception as e:
        response['message'] = 'Exception during chain replacement'
        response['error'] = e.args
        return jsonify(response), 400

    response ={'message': 'Chain replaced'}

    if not chain_replaced:
        response = {'message': 'No need to replace'}

    return jsonify(response), 200

@app.route('/chain/is_valid/', methods=['GET'])
def is_valid_request():
    is_valid = blockchain.is_chain_valid(blockchain.chain)

    response = {'message': 'Blockchain is valid'}

    if not is_valid:
        response ={'message': 'Blockchain ain\'t valid'}

    return jsonify(response), 200


@app.route('/chain/find_book/', methods=['POST'])
def find_book_in_chain():
    content = request.get_json()
    try: 
        book_tx, position = blockchain.find_last_book_transaction(content['hash'])
        if book_tx is None: 
            return f"Could not find requested book hash on chain. [{content['hash']}]", 400
    except Exception as e: 
        response = {
            'message': 'could not find a book',
            'error': str(e),
            'input': content
        }
        return jsonify(response), 400

    response = {
        'transaction': book_tx,
        'block_index': position
    }
    return jsonify(response), 200


@app.route('/chain/connect_node/', methods=['POST'])
def connect_node():
    content = request.get_json()
    nodes = content.get('nodes')
    if nodes is None:
        return 'No nodes', 400

    for node in nodes:
        blockchain.add_node(node)

    response = {
        'message': 'All the nodes are now connected:',
        'present_nodes': blockchain.nodes 
        }

    return jsonify(response), 201


@app.route('/chain/get_library_data', methods=['GET'])
def get_lib_data():
    print (blockchain.lib)
    response = {
        'message': 'Library data',
        'data': blockchain.lib
    } 
    return jsonify(response), 200

# TODO: Przetestować to tu 
@app.route('/chain/validate_transaction', methods=['POST'])
def validate_transaction():
    response = {
        'message': 'transaction is valid',
    }

    chain_replaced = blockchain.replace_chain()

    content =  request.get_json()
    print('CONTENT:', content)
    # transaction_keys = ['transaction']

    # if not all (key in content for key in transaction_keys):
    #     response['message'] = 'transaction key is missing in the payload'
    #     return jsonify(response), 400

    try:
        validator, signature = blockchain.validate_transaction(content)
    except Exception as e:
        response = {
            'message': 'Validation failed',
            'error': str(e),
            'input': content
        }
        return jsonify(response), 400

    response['validator'] = validator
    response['validator_sig'] = signature
    print('response !!!!!!!!!!')
    print(response)

    return jsonify(response), 200

@app.route('/chain/sync_tx/', methods=['POST'])
def sync_transactions():
    app.logger.debug('syncing transdactions')
    content = request.get_json()
    response = {
        'message': 'Transactions received and added',
    }

    try:
        _, ptx = blockchain.update_pending_transactions(content)
        response['pending_transactions'] = ptx 
    except Exception as e:
        response['message'] = "Could not add given transactions"
        response['error'] = str(e)
        response['input'] = content
        app.logger.error(f'Error in update {response}')
        return jsonify(response), 400 

    return jsonify(response), 200

## --- Book Transactions
# add mint transaction 
@app.route('/book/mint/', methods=['POST'])
def mint_book():
    content = request.get_json()
    
    try:
        index, pending_transactions = blockchain.add_mint_transaction(
            type=content['type'], 
            book=content['book']
        )
    except Exception as e:
        app.logger.error('Error while minting', e)
        response = {
            'message': 'could not mint a book',
            'error': str(e),
            'input': content

        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}',
        'pending_transactions': pending_transactions 
    }
    return jsonify(response), 201


@app.route('/book/reserve/', methods=['POST'])
def reserve_book():
    content =  request.get_json()
    transaction_keys = ['type', 'output', 'book']

    if not all (key in content for key in transaction_keys):
        return 'some elements of transaction are missing', 400

    if content['type'] != 1:
        return 'to place a reservation type of transaction must be: [1]', 400
    try: 
        index, pending_transactions = blockchain.add_reserve_transaction(
            type=content['type'], 
            book=content['book'],
            output=content['output']
        )
        print('pending transaction', pending_transactions)
    except Exception as e:
        print (e.args)
        response = {
            'message': 'could not make reservation',
            'error': e.args,
            'input': content
        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}',
        'pending_transactions': pending_transactions 
    }
    print(response)
    return jsonify(response), 201


@app.route('/book/rent/', methods=['POST'])
def rent_book():
    # transaction_keys = ['type', 'input', 'output', 'book']
    response = {
        'message': 'Nothin yet'
    }
    # return jsonify(response)
    content =  request.get_json()
    transaction_keys = ['type', 'output', 'book']
    # book_keys = ['isbn', 'hash', 'owner']
    # input_keys = ['tx_hash', 'use_condition', 'owner']
    # output_keys = ['target_lib_addr', 'use_condition', 'user_hash', 'days']

    if not all (key in content for key in transaction_keys):
        response['message'] = 'some elements of transaction are missing'
        return jsonify(response), 400

    if content['type'] != 2:
        response['message'] = 'to rent a book type of transaction must be: [2]'
        return jsonify(response), 400
    try: 
        index, pending_transactions = blockchain.add_rent_transaction(
            type=content['type'], 
            book=content['book'],
            output=content['output']
        )
    except Exception as e:
        response = {
            'message': 'could not make reservation',
            'error': e.args,
            'input': content

        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}',
        'pending_transactions': pending_transactions 
    }
    print(response)
    return jsonify(response), 201


@app.route('/book/pending_return/', methods=['POST'])
def pending_return():
    # transaction_keys = ['type', 'input', 'output', 'book']
    response = {
        'message': 'Nothin yet'
    }
    # return jsonify(response)
    content =  request.get_json()
    print(content)
    transaction_keys = ['type', 'book']

    if not all (key in content for key in transaction_keys):
        response['message'] = 'some elements of transaction are missing'
        return jsonify(response), 400

# TODO: this check is unncecessary - should happen in the transaction method
    if content['type'] != 3:
        response['message'] = 'to return a book, type of transaction must be: [3]'
        return jsonify(response), 400
    try: 
        index, pending_transactions = blockchain.add_pending_return_transaction(
            type=content['type'], 
            book=content['book'],
            output=content['output']
        )
    except Exception as e:
        response = {
            'message': 'could not make reservation',
            'error': e.args,
            'input': content

        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}',
        'pending_transactions': pending_transactions 
    }
    print(response)
    return jsonify(response), 201


@app.route('/book/return/', methods=['POST'])
def return_book():
    # transaction_keys = ['type', 'input', 'output', 'book']
    response = {
        'message': 'Nothin yet'
    }
    # return jsonify(response)
    content =  request.get_json()
    print(content)
    transaction_keys = ['type', 'book']
    # book_keys = ['isbn', 'hash', 'owner']
    # input_keys = ['tx_hash', 'use_condition', 'owner']
    # output_keys = ['target_lib_addr', 'use_condition', 'user_hash', 'days']

    if not all (key in content for key in transaction_keys):
        response['message'] = 'some elements of transaction are missing'
        return jsonify(response), 400

    if content['type'] != 4:
        response['message'] = 'to return a book, type of transaction must be: [3]'
        return jsonify(response), 400
    try: 
        index, pending_transactions = blockchain.add_return_transaction(
            type=content['type'], 
            book=content['book']
        )
    except Exception as e:
        response = {
            'message': 'could not make reservation',
            'error': e.args,
            'input': content

        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}',
        'pending_transactions': pending_transactions 
    }
    print(response)
    return jsonify(response), 201


@app.route('/book/burn/', methods=['POST'])
def burn_book():
    # transaction_keys = ['type', 'input', 'output', 'book']
    response = {
        'message': 'Nothin yet'
    }
    # return jsonify(response)
    content =  request.get_json()
    transaction_keys = ['type', 'book']
    # book_keys = ['isbn', 'hash', 'owner']
    # input_keys = ['tx_hash', 'use_condition', 'owner']
    # output_keys = ['target_lib_addr', 'use_condition', 'user_hash', 'days']

    if not all (key in content for key in transaction_keys):
        response['message'] = 'some elements of transaction are missing'
        return jsonify(response), 400

    if content['type'] != 5:
        response['message'] = 'to burn a book, type of transaction must be: [5]'
        return jsonify(response), 400
    try: 
        index, pending_transactions = blockchain.add_destroy_transaction(
            type=content['type'], 
            book=content['book']
        )
    except Exception as e:
        response = {
            'message': 'could not burn this book',
            'error': e.args,
            'input': content

        }
        return jsonify(response), 400

    response = {
        'message': f'Transaction will appear in block: {index}, Book will be destroyed on chain and not accessible further',
        'pending_transactions': pending_transactions 
    }
    print(response)
    return jsonify(response), 201


## Data store

@app.route('/datastore/get_books', methods=['GET'])
def get_books():

    # print(blockchain.books.keys())
    # print('--------')
    # print(blockchain.books.values())
    # for book in blockchain.books:
    #     print(book)
    response = {
        'books': blockchain.books,
    }

    return jsonify(response), 200


@app.route('/datastore/update_books/', methods=['GET'])
def update_books():

    list_updated = blockchain.update_book_store()

    response = {
        'message': 'Book store updated',
    }
    if not list_updated:
        response = {
            'message': 'Book store already up to date',
        }

    return jsonify(response), 200

app.run(host='0.0.0.0', port=node_port)
