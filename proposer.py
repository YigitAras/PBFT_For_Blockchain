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

    h = ""
    # R amount of rounds
    file_handle = open("chain_{}.txt".format(PORT_NUM),"w+")
    for _ in range(0,R):
        # H_O here empty

        # L lines long block
        block = h
        if h != "":
            block += "\n"
        for i in range(0,L):
            tx = "".join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
            block += tx + "\n"
        # below is the hash of both
        h = hashlib.sha256(block.encode('utf-8')).hexdigest()
        # signature of the thingy
        SIGNATURE = SECRETKEY.sign(block.encode('utf-8'))
        SIGNATURE_TO_SEND = binascii.hexlify(SIGNATURE).decode('utf-8')
        BLOCK_LIST = []
        BLOCK_LIST.append([block,1])
        # SEND BLOCK AND SIGN TO EVERYONE FIRST

        for i in range(1,len(PORT_KEY_TABLE)):
            cn = zmq.Context()
            sock = cn.socket(zmq.REQ)
            sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
            msg = {"BLOCK": block,"SIGN": SIGNATURE_TO_SEND}
            sock.send_json(json.dumps(msg))
            reply = ""
            reply = sock.recv()
            if reply != b'ACK':
                print("AN ERROR HAPPENED OH SHIT")
                quit()
            sock.close()
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

        # print("Second phase is done everyone recieved a TASK TYPE 1")
        # PREPARE EVERYONE FOR THE NEXT ROUND
        for i in range(1,len(PORT_KEY_TABLE)):
            cn = zmq.Context()
            sock = cn.socket(zmq.REQ)
            sock.connect("tcp://127.0.0.1:" + PORT_KEY_TABLE[i][0])
            # send the last hash here maybe
            msg = {"TYPE": 3}
            sock.send_json(json.dumps(msg))
            reply = json.loads(sock.recv_json())
            PUB_RECIEVED = binascii.unhexlify(reply["KEY"].encode('utf-8'))
            SIGN_RECIEVED = binascii.unhexlify(reply["SIGN"].encode('utf-8'))
            vk = ecdsa.VerifyingKey.from_string(PUB_RECIEVED, curve=ecdsa.NIST256p,hashfunc = hashlib.sha256)
            try:
                vk.verify(SIGN_RECIEVED,reply["BLOCK"].encode('utf-8'))
            except ecdsa.BadSignatureError:
                print("Recieved signature from the validator doesnt hold...")
                quit()
            found = False
            for elem in BLOCK_LIST:
                if elem[0] == reply["BLOCK"]:
                    elem[1] += 1
                    found = True
                    break
            if found == False:
                BLOCK_LIST.append([reply["BLOCK"],1])
            sock.close()
        for elem in BLOCK_LIST:
            if elem[1] >= (2 * ((N-1)//3)):
                file_handle.write(elem[0])

        # print("Third phase is done everyone recieved a TASK TYPE 3")
        print("One round is finished")
        if _ == (R-1):
            file_handle.write(h)

    # close the file handle when done
    print("Proposers rounds are complete, now run the tester.py")
    file_handle.close()






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
