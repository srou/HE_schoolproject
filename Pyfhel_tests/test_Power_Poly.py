"""Import all the packages useful for the Demo.
#-Pyfhel is useful to generate keys, encrypt and decrypt.
#-PyPtxt is useful to tranform the input vectors into plain text objects that could be encrypted.
#-PyCtxt is useful to tranform the plain text object in PyCtxt object that are encrypted (Cypher texts). PyCtxt can be add, multiply etc with homomorphic operations."""
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt

"""Other imports useful for the demo."""
from itertools import izip
import itertools
from operator import sub
import numpy as np
import matplotlib.pyplot as plt
import sys
import argparse
import copy

"""Define a parser to parse the arguments given to the program."""
parser = argparse.ArgumentParser()

""" One can specify in the command line of the program either -r or --random (it will be the same to specify -r or --random). This is optional argument. If the user specify it, args.random == True, else args.random == False)"""
parser.add_argument("-r", "--random", help="Perform tests on random vectors.", action="store_true")

""" One can specify in the command line of the program either -f or --fixe (it will be the same to specify -f or --fixe). This is optional argument. If the user specify it, args.fixe == True, else args.fixe == False)"""
parser.add_argument("-f", "--fixe", help="Perform tests on fixed vectors.", action="store_true")

"""One can view a pie chart of the successful tests versus fail tests by adding this option command."""
parser.add_argument("-g", "--graph", help="Display a pie chart of the successful tests versus fail tests..", action="store_true")

"""Parse the arguments given to the program."""
args = parser.parse_args()

"""If the user haven't specify (-r/--random) or (-f/--fixe) in the command line of the program, we run the tests with random vectors of size 5, with the elements between 0 and 1000 folowing an uniform law. Do the same if the user specify only -r/--random."""
if (not args.random and not args.fixe) or (args.random and not args.fixe):
                                                                          """Skip a line, print the title of the Demo, and skip a line again."""
                                                                          print("\n")
                                                                          print("     ************Pyfhel DEMO************")
                                                                          print("\n")

                                                                          """Define a vector that we will use for the tests (**=2, **=3)."""
                                                                          v_powerSquare = copy.deepcopy(v1)
                                                                          v_powerCube = copy.deepcopy(v1)

                                                                          """Define a vector that we will use for the tests (**=n)."""
                                                                          v_powern = copy.deepcopy(v1)

                                                                          """Define a vector that we will use for the tests (**2, **3)."""
                                                                          v_powerSquare2 = copy.deepcopy(v1)
                                                                          v_powerCube2 = copy.deepcopy(v1)

                                                                          """Define a vector that we will use for the tests (**n)."""
                                                                          v_powern2 = copy.deepcopy(v1)

                                                                          """Define a vector that we will use for the tests (polynomial)."""
                                                                          v_poly = copy.deepcopy(v1)

                                                                         
"""If the user have only specify (-f/--fixe) in the command line of the program, we run the tests with fixe vectors: [1.2.3.4.5], [2,2,2,2,2]."""
if (not args.random and args.fixe): 
                                     """Skip a line, print the title of the Demo, and skip a line again."""
                                     print("\n")
                                     print("     ************Pyfhel DEMO************")
                                     print("\n")

                                     """Define two vectors that we will use for the tests (+=, -=, *=, ...)."""
                                     v1 = [1,2,3,4,5]
                                     v2 = [2,2,2,2,2]

                                     """Define a vector that we will use for the tests (**n)."""
                                     v_powern2 = [1,2,3,4,4]

                                     """Define a vector that we will use for the tests (polynomial)."""
                                     v_poly = copy.deepcopy(v1)

                                     

"""If the user have specify (-r or --random) and (-f or --fixe) in the command line of the program, display an error."""
if (args.random and args.fixe):
                                 print("Error, you cannot specify -r/--random and -f/--fixe arguments at the same time.")
                                 sys.exit()


"""Define a variable to count the number of succes and the number of fail."""
number_success = 0
number_fail = 0


print("******Definition of the vectors used during the tests******")
print("v1: ", v1)
print("v2: ", v2)


"""Skip a line."""
print("\n")


#Instantiate a Pyfhel object called HE.
HE = Pyfhel()

print("******Generation of the keys for encryption******")

#Create the Key Generator parameters.
KEYGEN_PARAMS={ "p":257,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

"""Print the Key Generator parameters to let the user knows how his vectors will be encrypted."""
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)

"""Generate the keys that will be use to encrypted the vectors. The generation of the keys uses the Key Generator parameters. Then print a message to inform the user that the key generation has been completed."""
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")


"""Skip a line."""
print("\n")


"""We will first transform these two vectors in plaintext that could be encrypted, then we'll tranform the plain text of these two vectors in homeomorphic encrypted vector. Then we will add and multiply these two encrypted vectors in an homeomorphic way. Finally, we will decrypted the result of the addition and multiplication of the two encrypted vectors and we verify the result is the same that the addition or multiplication of the two vectors without encryption."""

print("******Homeomorphic encryption of the two vectors used during the tests******")

"""Tranform the vectors (use to test the operation **n) in plaintext that are objects that could be encrypted."""
ptxt_powern2 = PyPtxt(v_powern2, HE)
# v_powern2 = [1,2,3,4,4]

"""Tranform the vectors (use to test the operation polynomial) in plaintext that are objects that could be encrypted."""
ptxt_poly = PyPtxt(v_poly, HE)
#v_poly= [1,2,3,4,5]

"""Encrypted the plaintexts to have Cypher texts that are encrypted in an homeomorphic way with the key that have been generated before. These Cypher txt will be use for the tests on the homeomorphic operations (**n)"""
ctxt_powern2 = HE.encrypt(ptxt_powern2)

"""Encrypted the plaintexts to have Cypher texts that are encrypted in an homeomorphic way with the key that have been generated before. These Cypher txt will be use for the tests on the homeomorphic operations (polynomial)"""
ctxt_poly = HE.encrypt(ptxt_poly)


print("Encryption of v1...")
print("Encryption of v2...")

print("Encrypted v1: Encrypt(", v1, ")")
print("Encrypted v2: Encrypt(", v2, ")")


"""Skip a line."""
print("\n")


"""Perform homeomorphic operations on the encrypted vectors."""
print("******Test of the homeomorphic operations******")


"""Perform homeomorphic Power with the operator **4 ."""
print("***Test of the homeomorphic Power **4 ***")
print("Encrypted v1: Encrypt(", v_powern2, ")")
"""ctxt_power4 contains Encrypt(v1). So we perform: Encrypt(v1) ** 4"""
print("Performing Encrypt(v1) ** 4...")
ctxt_powern2_result = ctxt_powern2 ** 4
"""Decrypt the result of Power 4 of the encrypted vector."""
v_powern2_decrypt_result = HE.decrypt(ctxt_powern2_result)
"""v_powern2_decrypt_result is a list of list ie [[a, b, c,...]], so we want to flatten it to obtain [a, b, c,...]."""
v_powern2_decrypt_result_flatten = list(itertools.chain.from_iterable(v_powern2_decrypt_result))
print("Decrypt(Encrypt(v1) ** 4) -> ", v_powern2_decrypt_result_flatten)
"""Perform the Power4 on the unencrypted vectors."""
v_Powern2 = [a*b*c*d for a,b,c,d in izip(v_powern2, v_powern2, v_powern2, v_powern2)]
print("v1 ** 4 ->", v_Powern2)
"""If Decrypt(Encrypt(v1) ** 4) equal to v1 ** 4, The homeomorphic operation works and so it is a success. Else, it is a fail."""
if v_powern2_decrypt_result_flatten == v_Powern2:
   print("Homeomorphic operation Power with operator **4 is a success: Decrypt(Encrypt(v1) ** 4) equal to v1 ** 4.")
   number_success += 1
else:
   print("Homeomorphic operation Power with operator **4 is a fail: Decrypt(Encrypt(v1) ** 4) not equal to v1 ** 4.")
   number_fail += 1

"""Skip a line."""
print("\n")
print("Number of successful tests: ", number_success)
print("Number of fail tests: ", number_fail)
print("\n")


"""If the user has specify the -g option, we display a graph of the succesful tests versus the fail tests."""
if args.graph:
   # Pie chart, where the slices will be ordered and plotted counter-clockwise:
   labels = 'Success', 'Fails'
   sizes = [number_success, number_fail]
   explode = (0.1, 0)  # only "explode" the 1er slice (i.e. 'Success')

   fig1, ax1 = plt.subplots()
   ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90)
   ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
   plt.title("Succesful tests versus fail tests.")

   plt.show()
