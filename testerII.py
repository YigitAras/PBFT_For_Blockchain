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
def NORMAL_TESTER():
    HASH = [""] * N
    BLOCK = [""] * N
    CHECKER = True
    for i in range(0,R):
        for j in range(0,N):
            for k in range(0,L):
                BLOCK[j] += file_handle_list[j].readline()
            HASH[j] = file_handle_list[j].readline()
            temp_hash = str(hashlib.sha256(BLOCK[j].encode('utf-8')).hexdigest()) +"\n"
            if temp_hash.rstrip() != HASH[j].rstrip():
                CHECKER = False
            BLOCK[j] = HASH[j]
        if i == (R-1):
            checker = HASH[0]
            for z in range(1,N):
                if checker != HASH[z]:
                    printf("{}\'th hash is different".format(z))
                    CHECKER = False

    return CHECKER
start_loc = 5001

if len(sys.argv) != 5:
    print("Usage: python tester.py arg1 arg2 arg3 arg4\n\t where  ARG1 is N, ARG2 is R, ARG3 L and ARG4 is malicious user number")
    quit()

WHOLE_CHECKER = True

N = sys.argv[1]
R = sys.argv[2]
L = sys.argv[3]
MALICIOUS = sys.argv[4]
#check the validity of the input
try:
    N = int(N)
    R = int(R)
    L = int(L)
    MALICIOUS = int(MALICIOUS)
except:
    print("Please enter integers for N,R,L,MALICIOUS")
    quit() 


file_handle_list = []

# open all the files
for i in range(0,N):
    f_temp = open("chain_{}.txt".format(start_loc + i),"r")
    file_handle_list.append(f_temp)
    left_over = N-MALICIOUS
    first_part = math.ceil(left_over/2)
    # group 1 and group 2
    group_1 = range(MALICIOUS,(MALICIOUS+(first_part)))
    group_2 =range((MALICIOUS+(first_part)),N)


print("="*40)
for e in group_1:
    print(e)
print("="*40)
for e in group_2:
    print(e)
    
if MALICIOUS == 0:
    ses = NORMAL_TESTER()
    if ses == True:
        print("All good, test passed")
    else:
        print("Errors happened above prints explain the errors")

print("Proposer as well as {} peers are malicious".format(MALICIOUS-1))

print("Checking the first group:")

g1_first = file_handle_list[MALICIOUS].read()
file_handle_list[MALICIOUS].seek(0)

g2_first = file_handle_list[MALICIOUS+first_part].read()
file_handle_list[MALICIOUS+first_part].seek(0)
g1_cons = True
g2_cons = True
for i in group_1:
    line = file_handle_list[i].readline()
    if line.strip() == "NO CONSENSUS":
        print("No consensus reached in group 1")
        g1_cons = False
        break
    # GO BACK TO THE FIRST
    file_handle_list[i].seek(0)
    
    checker = file_handle_list[i].read()
    if checker != g1_first:
        print("BLOCKS ARENT EQUAL IN GROUP 1")
        WHOLE_CHECKER = False
    file_handle_list[i].seek(0)

if g1_cons == True:
    print("Consensus reached in GROUP 1")
    print("Checking validity of the hash chains now")
    # DO the hash check
    HASH = ""
    BLOCK = ""
    CHECKER = True
    for i in range(0,R):
        for k in range(0,L):
            BLOCK += file_handle_list[MALICIOUS].readline()
        sign = file_handle_list[MALICIOUS].readline()
        sign_ctr = 1
        if sign != "SIGNATURES--\n":
            print("File format is bad...")
        if sign == "SIGNATURES--\n":
            while True:
                tmp = file_handle_list[MALICIOUS].readline()
                if tmp != "SIGNATURES--\n":
                    sign_ctr += 1
                else:
                    if sign_ctr < (2 * ((N-1)//3))+1:
                        print("In Group 1's chain there are lower than ( 2K+1 ) signatures")
                        WHOLE_CHECKER = False
                    break
        HASH = file_handle_list[MALICIOUS].readline()
        temp_hash = str(hashlib.sha256(BLOCK.encode('utf-8')).hexdigest()) +"\n"
        if temp_hash.rstrip() != HASH.rstrip():
            CHECKER = False
        BLOCK = HASH
    if i == (R-1):
        if CHECKER == True:
            print("Alls well with Group 1's hash chain")
        else:
            print("Group 1's hash chain is not valid")
    

for i in group_2:
    line = file_handle_list[i].readline()
    if line.strip() == "NO CONSENSUS":
        print("No consensus reached in group 2")
        g2_cons = False
        break
    # GO BACK TO THE FIRST
    file_handle_list[i].seek(0)
    
    checker = file_handle_list[i].read()
    if checker != g1_first:
        print("BLOCKS ARENT EQUAL IN GROUP 2")
        WHOLE_CHECKER = False
        break
    file_handle_list[i].seek(0)
if g2_cons == True:
    print("Consensus reached in GROUP 2")
    print("Checking validity of the hash chains now")
    # DO the hash check
    HASH = ""
    BLOCK = ""
    CHECKER = True
    for i in range(0,R):
        for k in range(0,L):
            BLOCK += file_handle_list[MALICIOUS+first_part].readline()
        sign = file_handle_list[MALICIOUS+first_part].readline()
        sign_ctr = 1
        if sign != "SIGNATURES--\n":
            print("File format is bad...")
        if sign == "SIGNATURES--\n":
            while True:
                tmp = file_handle_list[MALICIOUS+first_part].readline()
                if tmp != "SIGNATURES--\n":
                    sign_ctr += 1
                else:
                    if sign_ctr < (2 * ((N-1)//3))+1:
                        print("In Group 2's chain there are lower than ( 2K+1 ) signatures")
                        WHOLE_CHECKER = False
                    break
        HASH = file_handle_list[MALICIOUS+first_part].readline()
        temp_hash = str(hashlib.sha256(BLOCK.encode('utf-8')).hexdigest()) +"\n"
        if temp_hash.rstrip() != HASH.rstrip():
            CHECKER = False
        BLOCK = HASH
    if i == (R-1):
        if CHECKER == True:
            print("Alls well with Group 2's hash chain")
        else:
            print("Group 2's hash chain is not valid")







if WHOLE_CHECKER == False:
    print("Tests are not passed")
else:
    print("Tests are passed,everything works as intended")
    
            

