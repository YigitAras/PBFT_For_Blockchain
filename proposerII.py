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

# REST API PORT
URL  = "http://127.0.0.1:5000"
DEST = "http://127.0.0.1"

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
# za zerva
def ZERVER():
    print("PORT num of the proposer: {}".format(PORT_NUM))
    # proposer means its the patient 0
    time.sleep(1)
    requests.put( URL+"/P2PSYS", json={"PEER":("{}".format(PORT_NUM),"{}".format(PUBLIC_TO_SEND))})

    #wait till enough people join in
    while True:
        if len(PORT_KEY_TABLE) == N:
            break
        else:
            time.sleep(1)
    print("Provided amount of peers joined...")
    if MALICIOUS == 0:
        is_MAL = False
    h = ""
    h2 = ""  # to bamboozle
    # R amount of rounds
    file_handle = open("chain_{}.txt".format(PORT_NUM),"w+")
    for _ in range(0,R):
        # H_O here empty

        # L lines long block
        GLOBL_FOUND = False
        block = h
        block2 = h2
        if h != "":
            block += "\n"
        for i in range(0,L):
            tx = "".join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
            block += tx + "\n"
        if h2 != "":
            block2 += "\n"
        for i in range(0,L):
            tx = "".join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
            block2 += tx + "\n"

        # below is the hash of both
        h = hashlib.sha256(block.encode('utf-8')).hexdigest()
        h2 = hashlib.sha256(block2.encode('utf-8')).hexdigest()
        # signature of the thingy
        SIGNATURE = SECRETKEY.sign(block.encode('utf-8'))
        SIGNATURE_TO_SEND = binascii.hexlify(SIGNATURE).decode('utf-8')
        SIGNATURE2 = SECRETKEY.sign(block2.encode('utf-8'))
        SIGNATURE_TO_SEND2 = binascii.hexlify(SIGNATURE2).decode('utf-8')
        BLOCK_LIST = []
        BLOCK_LIST.append([block,1,[]])
        BLOCK_LIST[0][2].append(SIGNATURE)
        BLOCK_LIST.append([block2,1,[]])
        BLOCK_LIST[1][2].append(SIGNATURE2)
        # SEND BLOCK AND SIGN TO EVERYONE FIRST
        # CALCULATED PPL TO KNOW WHAT TO SEND TO WHO
        left_over = len(PORT_KEY_TABLE)-MALICIOUS
        first_part = math.ceil(left_over/2)
        # group 1 and group 2
        group_1 = range(MALICIOUS,(MALICIOUS+(first_part)))
        group_2 =range((MALICIOUS+(first_part)),len(PORT_KEY_TABLE))
        print("Malicious: ",MALICIOUS)
        print("First group: ", group_1)
        print("Second group: ",group_2)
        for i in range(1,len(PORT_KEY_TABLE)):

            if i >= MALICIOUS:
                # NOT MALICIOUS
                cn = zmq.Context()
                sock = cn.socket(zmq.REQ)
                sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                # divide the group into two hehehe
                if i in group_1:
                    msg = {"BLOCK": block,"SIGN": SIGNATURE_TO_SEND}
                    print("SENT BLOCK1 to ",i)
                if i in group_2:
                    msg = {"BLOCK": block2,"SIGN": SIGNATURE_TO_SEND2}
                    print("SENT BLOCK2 to ",i)
                sock.send_json(json.dumps(msg))
                reply = ""
                reply = sock.recv()
                if reply != b'ACK':
                    print("Expected normal,recieved malicious")
                    quit()
                sock.close()
            elif i < MALICIOUS:
                # SEN ALL TO MALICIOUS
                cn = zmq.Context()
                sock = cn.socket(zmq.REQ)
                sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                msg = {"BLOCK": block,"SIGN": SIGNATURE_TO_SEND,
                       "BLOCK2": block2,"SIGN2": SIGNATURE_TO_SEND2}
                sock.send_json(json.dumps(msg))
                reply = ""
                reply = sock.recv()
                if reply != b'ACK_MAL':
                    print("Expected malicious,recieved normal")
                    quit()
                sock.close()
        print("Pre-prepare step is done....")
            #print("Recieved ACK from {}".format(PORT_KEY_TABLE[i][0]))
        # DONE FIRST LEVEL
        # EVERYONE HAS THEIR BLOCK AND
        # print("Initial phase is done, block and signature sent to everyone...")
        # start waiting thangs from people
        # THE JASON MODULE IS:
        # JSON = {"SIGN": SIGNATURE, "BLOCK": BLOCK , "TYPE":1}
        # TYPE 1 means the proposer is asking for an answer
        for i in range(1,len(PORT_KEY_TABLE)):
            cn = zmq.Context()
            sock = cn.socket(zmq.REQ)
            sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
            msg = {"BLOCK": block,"SIGN": SIGNATURE_TO_SEND,"TYPE": 1}
            sock.send_json(json.dumps(msg))
            inner_reply = ""
            inner_reply = sock.recv()
            if inner_reply != b"DONE_FORWARDING":
                print("One failed to accomplish his task,", PORT_KEY_TABLE[i][0])
                print("Expected DONE_FORWARDING recieved: ",inner_reply)
                quit()
            sock.close()
            print("PORT {} forwarded it's message to others".format(PORT_KEY_TABLE[i][0]))
            # check if your block matches the recieved block
        print("Prepare step is done...")
        # print("Second phase is done everyone recieved a TASK TYPE 1")
        # PREPARE EVERYONE FOR THE NEXT ROUND
        for i in range(1,len(PORT_KEY_TABLE)):
            if i < MALICIOUS:
                cn = zmq.Context()
                sock = cn.socket(zmq.REQ)
                sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                msg= {"TYPE": 3}
                sock.send_json(json.dumps(msg))
                reply = sock.recv()
                if reply != b"MAL_EXIT":
                    print("One malicious didn't exit properly")
                if reply == b"MAL_EXIT":
                    print("One malicious boi exit properly..")
                sock.close()
            elif i>=MALICIOUS:
                cn = zmq.Context()
                sock = cn.socket(zmq.REQ)
                sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
                # send the last hash here maybe
                msg = {"TYPE": 3}
                sock.send_json(json.dumps(msg))
                reply = json.loads(sock.recv_json())
                if reply["CONSENSUS"] == "REACHED":
                    PUB_RECIEVED = binascii.unhexlify(reply["KEY"].encode('utf-8'))
                    SIGN_RECIEVED = binascii.unhexlify(reply["SIGN"].encode('utf-8'))
                    vk = ecdsa.VerifyingKey.from_string(PUB_RECIEVED, curve=ecdsa.NIST256p,hashfunc = hashlib.sha256)
                    try:
                        vk.verify(SIGN_RECIEVED,reply["BLOCK"].encode('utf-8'))
                    except ecdsa.BadSignatureError:
                        print("Recieved signature from the validator doesnt hold...")
                        quit()
                    print("One honest boi exit properly..")
                    found = False
                    for elem in BLOCK_LIST:
                        if elem[0] == reply["BLOCK"]:
                            elem[1] += 1
                            found = True
                            elem[2].append(SIGN_RECIEVED)
                            break
                    if found == False:
                        nn = []
                        nn.append(SIGN_RECIEVED)
                        BLOCK_LIST.append([reply["BLOCK"],1,nn])
                else:
                    print("One honest exit properly, but it reported it did not reach a consensus")
                sock.close()
        found = False
        for elem in BLOCK_LIST:
            print("This many found: ", elem[1])
            if elem[1] >= (2 * ((N-1)//3)):
                found = True
                GLOBL_FOUND = True
                file_handle.write(elem[0])
                file_handle.write("SIGNATURES--\n")
                sign_list = elem[2]
                for el in sorted(sign_list):
                    file_handle.write(el.hex())
                    file_handle.wite("\n")
                file_handle.write("SIGNATURES--\n")
        if found == False:
            print("Didn't get >=2k+1 of any block....")
            print("Proposer boi also doesn't reach a consensus")

        # print("Third phase is done everyone recieved a TASK TYPE 3")
        print("Commit step is done...")
        print("One round is finished")
        if _ == (R-1):
            if GLOBL_FOUND == True:
                file_handle.write(h)
            else:
                file_handle.write("NO CONSENSUS\n")

    # close the file handle when done
    print("Proposer's rounds are complete, now run the testerII.py")
    file_handle.close()






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


SECRETKEY = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, hashfunc = hashlib.sha256)
PUBLIC = SECRETKEY.get_verifying_key()
PUBLIC_TO_SEND = binascii.hexlify(PUBLIC.to_string()).decode('utf-8')


#######################################################################
#=====================================================================#
#=====================================================================#
#================          JSON FORMAT             ===================#
#================   json["PEER"] = (PUBLIC,PORT)   ===================#
#================   the json["PEER"] is a tuple    ===================#
#=====================================================================#
#=====================================================================#
#######################################################################



# the table for holding main keys
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
#create the API
app = Flask(__name__)
api = Api(app)
class P2P_SYS(Resource):
    def put(self):
        resp = (request.get_json())
        # hold everything as a tuple
        #main_key_table[resp["PEER"][1]] = resp["PEER"]
        PORT_KEY_TABLE.append(resp["PEER"])
        #get everyone
    def get(self):
        # return the table directly for all access
        return json.dumps(PORT_KEY_TABLE)
        # delete yo-self
    def delete(self):
        resp = (request.get_json())
        #takes the port
        search_id = resp["PEER"][1]
        for elem in PORT_KEY_TABLE:
            if elem == search_id:
                del PORT_KEY_TABLE[search_id]
                return json.dumps({}),200
        return json.dumps({}),404

api.add_resource(P2P_SYS,'/P2PSYS')
t1 = threading.Thread(target=ZERVER)
t1.start()
t3 =threading.Thread(target=app.run(debug=True,use_reloader=False))
t3.start()
