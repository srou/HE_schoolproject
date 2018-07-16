import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np
from random import randint

def is_smaller(x_bits,y_bits,HE,alpha=4,n=1000):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    print("Initisalisation")
    p_1=PyPtxt([1], HE)
    c_1=HE.encrypt(p_1)
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        tmp1=c_1.copy(c_1)
        same_bit.append(tmp1-((x_bits[i]-y_bits[i])**2))
        tmp=c_1.copy(c_1)
        #print("c_1 : ",HE.decrypt(c_1))
        #print("tmp : ",HE.decrypt(tmp))
        for j in range(i+1):
            #print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        #print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]  ## peut etre un pb d'indice
        #print("res : ",HE.decrypt(res))
    return res

def coinToss(x_bits,n,HE,alpha=4):
#Takes in input an integer n, and an encrypted number 0=< x_bits <n as a list of alpha bits
#generates a random number r between 0 and n  (potentially drawn from a distribution D)
#Returns an encrypted bit b=[1] if r<x (ie : with probability x/n) otherwise [0]
    print("n="+str(n))
    r=randint(0, n)
    #encrypt r as a list of bits
    print("Encrypt "+str(r)+" as a list of bits.")
    a='{0:0'+str(alpha)+'b}'
    r_bits=[int(i) for i in list(a.format(r))] 
    r_bits_enc=[]
    for i in r_bits:
        p=PyPtxt([i], HE)
        r_bits_enc.append(HE.encrypt(p))
    #compare r_bits and x_bits
    return is_smaller(x_bits,r_bits_enc,HE)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha=4):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #L=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute (deg=1 : mean, deg=2 : 2nd order momentum)
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list
    
    #Initialize
    L=2**alpha
    c=int(math.floor((L**deg)/n))+1  #peut etre pas +1
    a=[]  
    p_0=PyPtxt([0], HE)
    res=HE.encrypt(p_0)
    print("c*n="+str(c*n))
    for i in range((c*n)):       #rq : pour L=8 et n=3, c=3 et c*n=9 (environ 440sec)
        tmp=int(math.floor(i/c))    #(rq le dernier i sera c*n-1 donc le dernier tmp sera n-1)
        print("tmp="+str(tmp))
        a.append(coinToss(list_x_bits[tmp],c*n,HE))
        res+=a[i]  #peut etre pas besoin d'une liste (sommer directement les elts dans res)
    return res

def k_smallest_values(list_d_bits,HE,deg,alpha=4):
    n=len(list_d_bits)
    avg=probabilisticAverage(list_d_bits,n,HE,1,alpha=alpha)
    second_moment=avg=probabilisticAverage(list_d_bits,n,HE,2,alpha=alpha)
    


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

#Create a list of int, each one encrypted bit by bit
list_x_bits=[]
list_nb=[4,8,12]  #we want to compute the average of these numbers
for k in list_nb:
    print ("Encrypting "+str(k)+" as a list of bits.")
    x_bits=[int(i) for i in list('{0:04b}'.format(k))]
    x_bits_enc=[]
    for i in x_bits:
        p=PyPtxt([i], HE)
        x_bits_enc.append(HE.encrypt(p))
    list_x_bits.append(x_bits_enc)

#Compute the probabilistic average of the list of int
start = time.time()
result=probabilisticAverage(list_x_bits,3,HE,1,L=8)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )