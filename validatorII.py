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
import math

# FOR API REACHING...
URL  = "http://127.0.0.1:5000"

if len(sys.argv) != 6:
    print("Usage: python proposer.py arg1 arg2 arg3 arg4 arg5\n\t where ARG1 is PORT, ARG2 is N, ARG3 is R, ARG4 L and ARG5 is malicious user number")
    quit()

PORT_NUM = sys.argv[1]
N = sys.argv[2]
R = sys.argv[3]
L = sys.argv[4]
MALICIOUS = sys.argv[5]
#check the validity of the input
try:
    N = int(N)
    R = int(R)
    L = int(L)
    MALICIOUS = int(MALICIOUS)
except:
    print("Please enter integers for N,R,L,MALICIOUS")
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
    is_MAL = False
    identification = int(PORT_NUM)
    if identification <= (5000+MALICIOUS):
        is_MAL = True

    if is_MAL==True:
        print("I am a malicious,dirty boi...")
    if MALICIOUS == 0:
        is_MAL = False
    left_over = len(PORT_KEY_TABLE)-MALICIOUS
    first_part = math.ceil(left_over/2)
    # group 1 and group 2
    group_1 = range(MALICIOUS,(MALICIOUS+(first_part)))
    group_2 =range((MALICIOUS+(first_part)),len(PORT_KEY_TABLE))

    file_handle = open("chain_{}.txt".format(PORT_NUM),"w+")
    # Listen to the server and get the BLOCK AND SIGN
    # json recieved will be =>> "BLOCK" and "SIGN"
    for _ in range(0,R):
        BLOCK = ""
        SIGN  = ""
        BLOCK2 = ""
        SIGN2 = ""
        GLOBL_FOUND = False
        # depends on if is_MAL is true
        if is_MAL == True:
            cn = zmq.Context()
            sock = cn.socket(zmq.REP)
            sock.bind("tcp://127.0.0.1:" + PORT_NUM)
            resp = {}
            resp = json.loads(sock.recv_json())
            SIGN = binascii.unhexlify(resp["SIGN"].encode('utf-8'))
            BLOCK = resp["BLOCK"]
            SIGN2 = binascii.unhexlify(resp["SIGN2"].encode('utf-8'))
            BLOCK2 = resp["BLOCK2"]
            print("Recieved the block from PROPOSER MALICIOUSLY, sending ACKNOWLEDGE")
            sock.send(b'ACK_MAL')
        else:
            cn = zmq.Context()
            sock = cn.socket(zmq.REP)
            sock.bind("tcp://127.0.0.1:" + PORT_NUM)
            resp = {}
            resp = json.loads(sock.recv_json())
            SIGN = binascii.unhexlify(resp["SIGN"].encode('utf-8'))
            BLOCK = resp["BLOCK"]
            print("Recieved the block from PROPOSER like a decent human being, sending ACKNOWLEDGE")
            sock.send(b'ACK')

        # the blocks seen up until now
        BLOCK_LIST = []
        BLOCK_LIST.append([BLOCK,1,[]])
        BLOCK_LIST[0][2].append(SIGN)
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
                # add yourself too because you are a pretty little thing as well
                BLOCK_LIST[0][1] += 1
                BLOCK_LIST[0][2].append(SELF_SIGNATURE)
                if is_MAL == True:
                    SELF_SIGNATURE2 = SECRETKEY.sign(BLOCK2.encode('utf-8'))
                    SELF_SIGNATURE_TO_SEND2 = binascii.hexlify(SELF_SIGNATURE2).decode('utf-8')
                print("Not sending malicious people anything, starting from: ",MALICIOUS)
                for i in range(MALICIOUS,len(PORT_KEY_TABLE)):
                    #start from first and dont send yourself
                    if PORT_KEY_TABLE[i][0] != PORT_NUM:
                        cn = zmq.Context()
                        level_sock = cn.socket(zmq.REQ)
                        level_sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                        #split the group
                        if is_MAL == True:
                            if i in group_1:
                                level_msg = {"SENDER": PORT_NUM, "BLOCK": BLOCK,
                                            "SIGN": SELF_SIGNATURE_TO_SEND, "TYPE": 2}
                            if i in group_2:
                                level_msg = {"SENDER": PORT_NUM, "BLOCK": BLOCK2,
                                            "SIGN": SELF_SIGNATURE_TO_SEND2, "TYPE": 2}
                        else:
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
                        elem[2].append(recieved_SIGN)
                        break
                if found == False:
                    nn = []
                    nn.append(recieved_SIGN)
                    BLOCK_LIST.append([resp["BLOCK"],1,nn])
                #print("Recieved TYPE 2, sending SUCC_RECIEVED")
                sock.send(b"SUCC_RECIEVED")


            elif resp["TYPE"] == 3:
                TERMINATE = "EXIT"
                found = False
                ctr = -1
                if is_MAL == False:
                    for i in range(0, len(BLOCK_LIST)):
                        if BLOCK_LIST[i][1] >= (2 * ((N-1)//3) + 1):
                            found = True
                            GLOBL_FOUND = True
                            BLOCK = BLOCK_LIST[i][0]
                            type3_msg = {"KEY":PUBLIC_TO_SEND , "SIGN": SELF_SIGNATURE_TO_SEND , "BLOCK": BLOCK_LIST[i][0], "CONSENSUS": "REACHED"}
                            sock.send_json(json.dumps(type3_msg))
                            ctr = i
                            break
                    if found == True:
                        file_handle.write(BLOCK_LIST[ctr][0])
                        file_handle.write("SIGNATURES--\n")
                        ll = BLOCK_LIST[i][2]
                        for el in sorted(ll):
                            file_handle.write(el.hex())
                            file_handle.write("\n")
                        file_handle.write("SIGNATURES--\n")
                        print("Consensus over a block reached...")
                    else:
                        print("Can't accept the block")
                        type3_msg = {"CONSENSUS": "FAILED"}
                        sock.send_json(json.dumps(type3_msg))
                else:
                    sock.send(b"MAL_EXIT")
            else:
                print("Fatal error unknown TYPE, exiting...")
                quit()

        print("One round complete, re-starting proc")
        sock.close()
        if _ == (R-1):
            if GLOBL_FOUND == True:
                hash = hashlib.sha256(BLOCK.encode('utf-8')).hexdigest()
                file_handle.write(hash)
            else:
                if is_MAL == False:
                    file_handle.write("NO CONSENSUS\n")
                else:
                    file_handle.write("MALICIOUS")

    file_handle.close()
    print("Did my time done my duty...")



ZERVER()
