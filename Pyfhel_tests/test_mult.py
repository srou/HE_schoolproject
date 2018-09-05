import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":17,      "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":50,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}  
print("  Running KeyGen with params:")
print(str(KEYGEN_PARAMS))
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )


a=HE.encrypt(PyPtxt([1], HE)) 
b=HE.encrypt(PyPtxt([2], HE)) 
start = time.time()
a*=b
end= time.time()
print("Multiplication in "+str(end-start)+" sec.")