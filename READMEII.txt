Call the proposer and the validator functions as follows;

python proposerII.py PORT NUMBER_OF_PEERS NUMBER_OF_ROUNDS LINES_IN_BLOCK NUMBER_OF_MALICIOUSPEERS
python validatorII.py PORT NUMBER_OF_PEERS NUMBER_OF_ROUNDS LINES_IN_BLOCK NUMBER_OF_MALICIOUSPEERS
(PORT HERE IS JUST THE PORT NUM LIKE 5001 NOT THE WHOLE ADRESS)

Please start proposer from port 5001, then open other validators by incrementing this by 1;
proposer -> 5001 , validator1 -> 5002 ... etc
This naming convention is for the TESTER.PY script which will read the files and check if the values are holding properly.

For tester please run the command as follows:
python testerII.py NUMBER_OF_PEERS NUMBER_OF_ROUNDS LINES_IN_BLOCK NUMBER_OF_MALICIOUSPEERS

(Note that after starting proposer you have to wait 1 sec for API server to start then start other validators)

scripts will print as they recieve messages and send messages to make sure we know if something goes wrong


 
