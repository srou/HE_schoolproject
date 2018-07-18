import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np
from random import randint

def is_smaller(x_bits,y_bits,HE,alpha=5,n=1000):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    #print("Initisalisation of is_smaller")
    p_1=PyPtxt([1], HE)
    c_1=HE.encrypt(p_1)
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    #print("x_bits[0] : ",HE.decrypt(x_bits[0]))
    #print("y_bits[0] : ",HE.decrypt(y_bits[0]))
    #print("res : ",HE.decrypt(res))
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
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]
            #print("res : ",HE.decrypt(res))
    return res

def l1_norm(a_enc,a_enc_bits,b,b_bits,HE,alpha):
    #a_enc : encrypted vector a (list of Ctxt where each Ctxt is an encrypted coefficient of a)
    #a_enc : encrypted bits of each elt of a (list of lists of Ctxt)
    #same for b and b_bits 
    res=0
    for i in range(len(b)):
        iss=is_smaller(b_bits[i],a_enc_bits[i],HE,alpha=alpha,n=1000)
        tmp=a_enc[i]-b[i]+2*((b[i]-a_enc[i])*iss)
        res+=tmp
    return res

def knn(q_enc,q_bits_enc,X_train,Y_train,HE_scheme,p,n,d,k=3,alpha=4,a_class=1):
    #q_enc =(enc(q1), ,enc(qd)) : list of the encrypted components of q
    #q_bits=([[q1_bits]], ,[[qd_bits]]) : list of lists, where [[q1_bits]] is the list of each encrypted bit of q1
    #X_train : training set (list of rows, each row being a list itself)
    #Y_train : labels associated with X_train
    #n,d : dimensions of X_train (n : nb of rows, d : nb of columns)
    #k : nb of nearest neighbors to output
    #alpha : nb of bits recquired to encode the input data
    #a_class : nb of bits recquired to encode the number of classes (??) (ex : if 2 classes, a_class=1)
    #p : prime number such that each value in X_train and q are between 0 and sqrt(p)/d
    #HE_scheme : scheme used for encryption (Pyfhel object)
    
    #Step 1 : calculate distances between q and the rows of X_train
    #initialize distances 
    distances=[]
    for i in range(n):
        #encrypt X_train[i] 
        b_enc=[]
        b_bits_enc=[]
        for elt in X_train[i]:
            #encrypt each elt of X_train[i] as a single cyphertext
            ptxt=PyPtxt([elt], HE)  #attention à ce que X_train ne contienne que des entiers
            b_enc.append(HE.encrypt(ptxt))
            #also encrypt each elt of X_train[i] as a list of encrypted bits
            a='{0:0'+str(alpha)+'b}'
            elt_bits=[int(i) for i in list(a.format(elt))] 
            print(elt,elt_bits)
            elt_bits_enc=[]
            for k in elt_bits:
                p=PyPtxt([k], HE)
                elt_bits_enc.append(HE.encrypt(p))
            b_bits_enc.append(elt_bits_enc)
        #compute dist(q,X_train[i])
        dist=l1_norm(q_enc,q_bits_enc,b_enc,b_bits_enc,HE=HE_scheme,alpha=alpha)
        distances.append(dist)
    return distances

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
print("")

alpha=4

q=[3,6,2]
X_train=[[3,6,2],[7,0,1],[5,12,3]]
Y_train=[1,0,0]
#encypt q
q_enc=[]
q_bits_enc=[]
for elt in q:
    #encrypt each elt of q as a single cyphertext
    ptxt=PyPtxt([elt], HE) 
    q_enc.append(HE.encrypt(ptxt))
    #also encrypt each elt of q as a list of encrypted bits
    a='{0:0'+str(alpha)+'b}'
    elt_bits=[int(i) for i in list(a.format(elt))] 
    print(elt,elt_bits)
    elt_bits_enc=[]
    for k in elt_bits:
        p=PyPtxt([k], HE)
        elt_bits_enc.append(HE.encrypt(p))
    q_bits_enc.append(elt_bits_enc)

#encypt X1
x1_enc=[]
x1_bits_enc=[]
for elt in X_train[1]:
    #encrypt each elt of q as a single cyphertext
    ptxt=PyPtxt([elt], HE) 
    x1_enc.append(HE.encrypt(ptxt))
    #also encrypt each elt of q as a list of encrypted bits
    a='{0:0'+str(alpha)+'b}'
    elt_bits=[int(i) for i in list(a.format(elt))] 
    print(elt,elt_bits)
    elt_bits_enc=[]
    for k in elt_bits:
        p=PyPtxt([k], HE)
        elt_bits_enc.append(HE.encrypt(p))
    x1_bits_enc.append(elt_bits_enc)

#encypt X2
x2_enc=[]
x2_bits_enc=[]
for elt in X_train[1]:
    #encrypt each elt of q as a single cyphertext
    ptxt=PyPtxt([elt], HE) 
    x2_enc.append(HE.encrypt(ptxt))
    #also encrypt each elt of q as a list of encrypted bits
    a='{0:0'+str(alpha)+'b}'
    elt_bits=[int(i) for i in list(a.format(elt))] 
    print(elt,elt_bits)
    elt_bits_enc=[]
    for k in elt_bits:
        p=PyPtxt([k], HE)
        elt_bits_enc.append(HE.encrypt(p))
    x2_bits_enc.append(elt_bits_enc)

print("Test l1-norm")
start = time.time()
result=l1_norm(q_enc,q_bits_enc,x1_enc,x1_bits_enc,HE=HE,alpha=4)
decrypted_res=HE.decrypt(result)
print("Distance (q,x1) : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )

start = time.time()
result=l1_norm(q_enc,q_bits_enc,x2_enc,x2_bits_enc,HE=HE,alpha=4)
decrypted_res=HE.decrypt(result)
print("Distance (q,x2) : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )


print("Test knn")
start = time.time()
result=knn(q_enc,q_bits_enc,X_train,Y_train,HE,1023,3,3,k=3,alpha=4,a_class=1)
decrypted_res=HE.decrypt(result)
print("Distances between q and elements of X_train : ")
for res in result :
    print(HE.decrypt(res))
end=time.time()
print(str(end-start)+" sec." )

