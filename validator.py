import sys
import hashlib
import time
import zmq
import requests
import json
import os
from multiprocessing import Process
from flask import Flask,request
from flask_restful import Resource, Api
import threading
import time
import ecdsa
import random
import string
import sys
import binascii

# FOR API REACHING...
URL  = "http://127.0.0.1:5000"

if len(sys.argv) != 5:
    print("Usage: python proposer.py arg1 arg2 arg3 arg4\n\t where ARG1 is PORT, ARG2 is N, ARG3 is R and ARG4 L")
    quit()

PORT_NUM = sys.argv[1]
N = sys.argv[2]
R = sys.argv[3]
L = sys.argv[4]
#check the validity of the input
try:
    N = int(N)
    R = int(R)
    L = int(L)
except:
    print("Please enter integers for N,R,L")
    quit()


# CREATE THE PUBLIC AND SECRET KEYS
SECRETKEY = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, hashfunc = hashlib.sha256)
PUBLIC = SECRETKEY.get_verifying_key()
PUBLIC_TO_SEND = binascii.hexlify(PUBLIC.to_string()).decode('utf-8')

# REMINDER 1)
################################################################
# HOLDING: HEXLIFIED -> DECODE || NEED TO: ENCODE -> UNHEXLIFY #
################################################################

# REMINDER 2)
##########################################################
# FIRST ELEMENT OF THE MAIN TABLE IS ALWAYS THE PROPOSER #
##########################################################

# REMINDER 3)
##########################################################
#  WAIT ALL THE VALIDATORS ARE IN (VALIDATORS AS WELL)   #
##########################################################


# list of tuples to hold the public keys and ports
PORT_KEY_TABLE = []
"""
# ============================================================================================================
# DONT USE THE 0'TH SOCKET SINCE ITS THE MAIN ONE....
# SAME INDEXING APPLIES BETWEEN SOCKET LIST AND PORTKEY TABLE
def create_socket(ip):
    cn = zmq.Context()
    sock = cn.socket(zmq.REQ)
    sock.connect("tcp://" + ip)
##    print(ip)
    return sock

def fan_of_sockets():
    # get from port key table and fill the socket list
    global SOCKET_LIST,PORT_KEY_TABLE
    # do a cleanup
    if(len(SOCKET_LIST)!=0):
        for sock in SOCKET_LIST:
            sock[0].close()
    #create a list of socket and its IP
    for i in range(0,len(PORT_KEY_TABLE)):
        SOCKET_LIST.append([create_socket("127.0.0.1:" + PORT_KEY_TABLE[i][0]),PORT_KEY_TABLE[i][0]])
# ============================================================================================================
"""


def ZERVER():
    # PUT yourself to the PEER system through API

    requests.put( URL+"/P2PSYS", json={"PEER":("{}".format(PORT_NUM),"{}".format(PUBLIC_TO_SEND))})
    # request the list and fill your own with it
    # wait till all the peers are in
    TERMINATE = ""
    while True:
        # get the updated keys
        PORT_KEY_TABLE = json.loads(requests.get(URL+"/P2PSYS").json())
        if len(PORT_KEY_TABLE) != N:
            time.sleep(1)
        else:
            break
    file_handle = open("chain_{}.txt".format(PORT_NUM),"w+")
    # Listen to the server and get the BLOCK AND SIGN
    # json recieved will be =>> "BLOCK" and "SIGN"
    for _ in range(0,R):
        BLOCK = ""
        SIGN  = ""
        cn = zmq.Context()
        sock = cn.socket(zmq.REP)
        sock.bind("tcp://127.0.0.1:" + PORT_NUM)
        resp = {}
        resp = json.loads(sock.recv_json())
        SIGN = binascii.unhexlify(resp["SIGN"].encode('utf-8'))
        BLOCK = resp["BLOCK"]
        #print("Recieved the block from PROPOSER, sending ACKNOWLEDGE")
        sock.send(b'ACK')

        # the blocks seen up until now
        BLOCK_LIST = []
        BLOCK_LIST.append([BLOCK,1])
        # Recieved the BLOCK and SHITE
        TERMINATE = ""
        while TERMINATE != "EXIT":
            # NOW SEND OTHER FELLAS EVERYTHING
            resp = {}
            resp = json.loads(sock.recv_json())
            print("Recieved task of TYPE:{}".format(resp["TYPE"]))
            if resp["TYPE"] == 1:
                # Recieved from the PROPOSER
                # Now how to check and do check ups with others
                # A.k.a. CASCADE THE SHIT OUT OF EVERYONE
                PUB_OF_PROP = binascii.unhexlify(PORT_KEY_TABLE[0][1].encode('utf-8'))
                vk = ecdsa.VerifyingKey.from_string(PUB_OF_PROP, curve=ecdsa.NIST256p,hashfunc = hashlib.sha256)
                try:
                    vk.verify(SIGN,BLOCK.encode('utf-8'))
                except ecdsa.BadSignatureError:
                    print("Recieved signature from the proposer doesnt hold...")
                    quit()
                # now sign yourself and forward
                SELF_SIGNATURE = SECRETKEY.sign(BLOCK.encode('utf-8'))
                SELF_SIGNATURE_TO_SEND = binascii.hexlify(SELF_SIGNATURE).decode('utf-8')

                for i in range(1,len(PORT_KEY_TABLE)):
                    #start from first and dont send yourself
                    if PORT_KEY_TABLE[i][0] != PORT_NUM:
                        cn = zmq.Context()
                        level_sock = cn.socket(zmq.REQ)
                        level_sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                        level_msg = {"SENDER": PORT_NUM, "BLOCK": BLOCK,
                                     "SIGN": SELF_SIGNATURE_TO_SEND, "TYPE": 2}
                        level_sock.send_json(json.dumps(level_msg))
                        # forwarded the shite
                        level_rep = ""
                        level_rep = level_sock.recv()
                        level_sock.close()
                        if level_rep != b"SUCC_RECIEVED":
                            print("They played us like a fiddle chief...")
                            quit()
                # DONE WITH THE FORWARDING NOW WAIT FROM OTHERS....
                #print("Sent everyone type 2, returning DONE_FORWARDING to PROPOSER")
                sock.send(b"DONE_FORWARDING")


            elif resp["TYPE"] == 2:
                # Recieved from the VALIDATORS
                # Just return an answer to the one you recieved
                recieved_from = resp["SENDER"]
                recieved_KEY = ""
                recieved_SIGN = binascii.unhexlify(resp["SIGN"].encode("utf-8"))
                for elem in PORT_KEY_TABLE:
                    if elem[0] == recieved_from:
                        recieved_KEY = binascii.unhexlify(elem[1].encode("utf-8"))
                recieved_from_block = resp["BLOCK"]
                try:
                    vk = ecdsa.VerifyingKey.from_string(recieved_KEY, curve=ecdsa.NIST256p,hashfunc = hashlib.sha256)
                    vk.verify(recieved_SIGN,recieved_from_block.encode('utf-8'))
                except ecdsa.BadSignatureError:
                    print("Recieved signature from the validator doesnt hold...")
                    quit()
                found = False
                for elem in BLOCK_LIST:
                    if elem[0] == recieved_from_block:
                        elem[1] += 1
                        found = True
                        break
                if found == False:
                    BLOCK_LIST.append([recieved_from_block,1])
                #print("Recieved TYPE 2, sending SUCC_RECIEVED")
                sock.send(b"SUCC_RECIEVED")


            elif resp["TYPE"] == 3:
                TERMINATE = "EXIT"
                ctr = -1
                for i in range(0, len(BLOCK_LIST)):
                    if BLOCK_LIST[i][1] >= (2 * ((N-1)//3)):
                        ctr = i
                SELF_SIGNATURE = SECRETKEY.sign(BLOCK_LIST[i][0].encode('utf-8'))
                SELF_SIGNATURE_TO_SEND = binascii.hexlify(SELF_SIGNATURE).decode('utf-8')
                type3_msg = {"KEY":PUBLIC_TO_SEND , "SIGN": SELF_SIGNATURE_TO_SEND , "BLOCK": BLOCK}
                sock.send_json(json.dumps(type3_msg))
                file_handle.write(BLOCK)
            else:
                print("Fatal error unknown TYPE, exiting...")
                quit()

        print("One round complete, re-starting proc")
        sock.close()
        if _ == (R-1):
            hash = hashlib.sha256(BLOCK.encode('utf-8')).hexdigest()
            file_handle.write(hash)

    file_handle.close()
    print("Did my time done my duty...")



ZERVER()
