import sys
import hashlib
import os
import time
import ecdsa


start_loc = 5001

if len(sys.argv) != 4:
    print("Usage: python tester.py arg1 arg2 arg3\n\t where ARG1 is N, ARG2 is R and ARG3 L")
    quit()

N = sys.argv[1]
R = sys.argv[2]
L = sys.argv[3]
#check the validity of the input
try:
    N = int(N)
    R = int(R)
    L = int(L)
except:
    print("Please enter integers for N,R,L")
    quit()

file_handle_list = []

# open all the files
for i in range(0,N):
    f_temp = open("chain_{}.txt".format(start_loc + i),"r")
    file_handle_list.append(f_temp)

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

print("The result is {}".format(CHECKER))
