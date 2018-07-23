import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np

def is_smaller(x_bits,y_bits,HE,alpha,n=1000):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    print("Initisalisation")
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        same_bit.append(HE.encrypt(PyPtxt([1], HE))-((x_bits[i]-y_bits[i])**2))
        tmp=HE.encrypt(PyPtxt([1], HE))
        #print("tmp : ",HE.decrypt(tmp))
        for j in range(i+1):
            print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(HE.encrypt(PyPtxt([1], HE))-y_bits[i])*x_bits[i]*same_prefix[i]
            print("res : ",HE.decrypt(res))
    return res


start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":40,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

#test is_smaller with 2 integers
x=12
y=5
alpha=4
print("Test is_smaller with integers "+str(x)+" and "+str(y)+".")

x_bits=[int(i) for i in list('{0:04b}'.format(x))] #int 6 as a list of 8 bits
x_bits_enc=[]
print("Encrypting "+str(x)+" in bits ",x_bits)
start = time.time()
for i in x_bits:
    p=PyPtxt([i], HE)
    x_bits_enc.append(HE.encrypt(p))
end=time.time()
print(str(end-start)+" sec." )

y_bits=[int(i) for i in list('{0:04b}'.format(y))] #int 5 as a list of 8 bits
y_bits_enc=[]
print("Encrypting "+str(y)+" in bits.",y_bits)
start = time.time()
for i in y_bits:
    p=PyPtxt([i], HE)
    y_bits_enc.append(HE.encrypt(p))
end=time.time()
print(str(end-start)+" sec." )

result=is_smaller(x_bits_enc,y_bits_enc,HE,alpha)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)