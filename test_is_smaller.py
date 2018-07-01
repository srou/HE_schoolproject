import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np

def is_smaller(x_bits,y_bits,HE,n=10):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation 
    print("Initisalisation")
    p_1=PyPtxt(1,HE)   
    c_1=HE.encrypt(p_1) #encrypt 1
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]   ##peut etre faire deepcopy ??
    for i in range(math.floor(math.log(n))+1):
        same_bit.append(c_1-((x_bits[i]-y_bits[i])**2))   ### !!!! voir si la fct **2 marche pour les Ctxt
        tmp=c_1
        for j in range(i+1):
            tmp=tmp*same_bit[j]
        same_prefix.append(tmp)
        res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]  ## peut etre un pb d'indice
    return res

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":30,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

p_test=PyPtxt([1],HE)
c_test=HE.encrypt(p_test)
print("c_test = ",c_test.getIDs(),c_test.getLen())

#test is_smaller with integers 5 and 6
x=5
x_bits=[int(i) for i in list('{0:08b}'.format(x))] #int 5 as a list of bits
print("Encrypting "+str(x)+" in bits.")
start = time.time()
p_bit=PyPtxt(x_bits,HE)
x_bits_enc=HE.encrypt(p_bit)
print("x_bits_enc = ",x_bits_enc.getIDs(),x_bits_enc.getLen())
end=time.time()
print(str(end-start)+" sec." )

y=6
y_bits=[int(i) for i in list('{0:08b}'.format(y))] #int 6 as a list of bits
print("Encrypting "+str(y)+" in bits.")
start = time.time()
p_bit=PyPtxt(y_bits,HE)
y_bits_enc=HE.encrypt(p_bit)
print("x_bits_enc = ",y_bits_enc.getIDs(),x_bits_enc.getLen())
end=time.time()
print(str(end-start)+" sec." )

result=is_smaller(x_bits_enc,y_bits_enc,HE)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)