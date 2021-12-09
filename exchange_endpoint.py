from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)
    payload = json.dumps(message_dict['payload'])
    log_obj = Log(message=payload)
    g.session.add(log_obj)
    g.session.commit()

    # TODO: Add message to the Log table
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

def check_sig(payload,signature):
    if(payload['platform']=="Ethereum"):
        eth_account.Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = eth_account.Account.create_with_mnemonic()
        senderPubKey = payload['sender_pk']
        # eth_pk = senderPubKey
        # eth_sk = signature
        eth_pk = acct.address
        eth_sk = acct.key
        p=json.dumps(payload)
        eth_encoded_msg = eth_account.messages.encode_defunct(text=p)
        eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg,eth_sk)
        if (eth_account.Account.recover_message(eth_encoded_msg,signature=eth_sig_obj.signature.hex())) == eth_pk:
            return True

    if(payload['platform']=="Algorand"):
        algo_sk, algo_pk = algosdk.account.generate_account()
        # algo_sk = payload['sender_pk']
        # algo_pk= payload['sender_pk']
        p=json.dumps(payload)
        algo_sig_str = algosdk.util.sign_bytes(p.encode('utf-8'),algo_sk)

        if (algosdk.util.verify_bytes(p.encode('utf-8'),algo_sig_str,algo_pk)):
            return True


    return False

""" End of Helper methods"""
  
# @app.route('/address', methods=['POST'])
# def address():
#     if request.method == "POST":
#         content = request.get_json(silent=True)
#         if 'platform' not in content.keys():
#             print( f"Error: no platform provided" )
#             return jsonify( "Error: no platform provided" )
#         if not content['platform'] in ["Ethereum", "Algorand"]:
#             print( f"Error: {content['platform']} is an invalid platform" )
#             return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
#         if content['platform'] == "Ethereum":
#             #Your code here
#             return jsonify( eth_pk )
#         if content['platform'] == "Algorand":
#             #Your code here
#             return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    # get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                log_message(content)
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                log_message(content)
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # 2. Add the order to the table
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        signature = content['sig']
        payload = content['payload']
        senderPubKey = content['payload']['sender_pk']
        receiver = content['payload']['receiver_pk']
        buyCurrency = content['payload']['buy_currency']
        sellCurrency = content['payload']['sell_currency']
        buyAmount = content['payload']['buy_amount']
        sellAmount = content['payload']['sell_amount']
        verifyer = check_sig(payload,signature)
        if(verifyer):
            newOrder={}
            newOrder = Order(receiver_pk=receiver,sender_pk=senderPubKey,buy_currency=buyCurrency,sell_currency=sellCurrency,buy_amount=buyAmount,sell_amount=sellAmount)
            g.session.add(newOrder)
            g.session.commit()
            return jsonify(True)
        else:
            log_message(content)
            return jsonify(False)
    

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk" ]
    # Same as before
    resultDb = {"data": g.session.query(Order).all()}
    resultArray=[]
    
    for x in resultDb['data']:
        resultDictx={}
        resultDictx['sender_pk']=x.sender_pk
        resultDictx['receiver_pk']=x.receiver_pk
        resultDictx['buy_currency']=x.buy_currency
        resultDictx['sell_currency']=x.sell_currency
        resultDictx['buy_amount']=x.buy_amount
        resultDictx['sell_amount']=x.sell_amount
        resultDictx['signature']=x.signature
        resultArray.append(resultDictx)
    result = {"data":resultArray}
    # print("RESULT",result)
    
    return jsonify(result)
    # pass

if __name__ == '__main__':
    app.run(port='5002')
