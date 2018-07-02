import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np

##pb : how to choose n ??
def is_smaller(x_bits,y_bits,HE,alpha=8,n=1000):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation 
    print("Initisalisation")
    p_1=PyPtxt([1],HE)   
    c_1=HE.encrypt(p_1) #encrypt 1
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]              ##peut etre faire deepcopy ??
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        same_bit.append(c_1-((x_bits[i]-y_bits[i])**2))
        tmp=c_1.copy()
        print("c_1 : ",HE.decrypt(c_1))
        print("tmp : ",HE.decrypt(tmp))
        for j in range(i+1):
            print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]  ## peut etre un pb d'indice
        print("res : ",HE.decrypt(res))
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

#test [0]*[1]
#v5=[0]
#v6=[1]
#p5 = PyPtxt(v5, HE)
#p6 = PyPtxt(v6, HE)
#print("Encrypting v5: ", v5)
#c5 = HE.encrypt(p5)
#print("Encrypting v6: ", v6)
#c6 = HE.encrypt(p6)
#c5*=c6
#print("multiplication v5*v6 : ",HE.decrypt(c5))

#test is_smaller with integers 5 and 6
x=6
x_bits=[int(i) for i in list('{0:08b}'.format(x))] #int 5 as a list of 8 bits
x_bits_enc=[]
print("Encrypting "+str(x)+" in bits ",x_bits)
start = time.time()
for i in x_bits:
    print([i])
    p_bit=PyPtxt([i],HE)
    c_bit=HE.encrypt(p_bit)
    x_bits_enc.append(c_bit)
#print("x_bits_enc = ",x_bits_enc.getIDs(),x_bits_enc.getLen())
end=time.time()
print(str(end-start)+" sec." )

y=5
y_bits=[int(i) for i in list('{0:08b}'.format(y))] #int 6 as a list of 8 bits
y_bits_enc=[]
print("Encrypting "+str(y)+" in bits.",y_bits)
for i in y_bits:
    p_bit=PyPtxt([i],HE)
    c_bit=HE.encrypt(p_bit)
    y_bits_enc.append(c_bit)
#print("x_bits_enc = ",y_bits_enc.getIDs(),x_bits_enc.getLen())
end=time.time()
print(str(end-start)+" sec." )

result=is_smaller(x_bits_enc,y_bits_enc,HE)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)