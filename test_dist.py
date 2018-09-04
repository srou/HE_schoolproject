import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np
from random import randint

#test knn writing file


def encrypt_as_bits(x,alpha,HE,f):
    #takes in input a plaintext integer x =< 2^alpha -1
    #returns a list of the encrypted bits of x
    a='{0:0'+str(alpha)+'b}'
    x_bits=[int(i) for i in list(a.format(x))]
    x_bits_enc=[]
    f.write("Encrypting "+str(x)+" in bits "+str(x_bits))
    f.write("\n")
    f.flush()
    for i in x_bits:
        x_bits_enc.append(HE.encrypt(PyPtxt([i], HE)))
    return x_bits_enc
    
def is_smaller_fast1(x_bits,y_bits,HE,alpha):
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_bit =np.subtract(np.asarray(x_bits),np.asarray(y_bits))**2
    same_bit=np.subtract(np.asarray([c_1.copy(c_1) for i in range(alpha)]),same_bit)
    same_prefix=np.asarray([c_1.copy(c_1)]+[np.prod(same_bit[0:i+1]) for i in range(alpha-1)])
    to_sum=np.multiply(same_prefix,np.multiply(np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),np.asarray(y_bits)),np.asarray(x_bits)))
    res = np.sum(to_sum)
    return res

def bezout(a, b):
    #computes (u,v,p) st a*u + b*v = gdc(a,b)
    if a == 0 and b == 0: return (0, 0, 0)
    if b == 0: return (a/abs(a), 0, abs(a))
    (u, v, gdc) = bezout(b, a%b)
    return (v, (u - v*(a/b)), gdc)
def inv_modulo(x, p):
    #Computes y in [p] st x*y=1 mod p
    (u, _, gdc) = bezout(x, p)
    if gdc == 1: return u%abs(p)
    else: raise Exception("%s et %s are not mutually prime" % (x, p))
        
def convert_to_bits(x,p,alpha,HE,f):
    def coeffs_Pbit_i(i,p,alpha,f):
        #Returns the coefficients ri that will help compute the polynomial P_bit that interpolates the function f:x-->bit_i(x) on [p]
        #alpha : nb of bits
        #0=< 2^alpha-1 < p, p prime
        #0=< i =< alpha
        l1=range(0,p)
        a='{0:0'+str(alpha)+'b}'
        l2=[int(list(a.format(x))[i]) for x in l1]
        #f.write("l2 : "+str(l2))
        #f.write("\n")
        f.flush()
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[]
        #f.write("Computing coefficients of Pbit_i") 
        for i in range(p):
            num=l2[i]
            den=1
            for j in range(p):
                if i!=j:
                    den*=i-j
            tmp=(num*inv_modulo(den,p))%p
            r.append(int(tmp))
        return r
    def compute_Pbit_i(x,p,coeffs_i,HE):
        #0=< x =< 2^alpha-1 < p  , p prime
        #returns [1] if the ith bit of x is 1, otherwise 0 (x coded on alpha bits)
        res=HE.encrypt(PyPtxt([0], HE)) 
        for i in range(0,p) :
            tmp=HE.encrypt(PyPtxt([coeffs_i[i]], HE))
            for j in range(p):
                if i!=j:
                    tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            res+=tmp
        return res
    #takes in input an encrypted number x and returns its representation as a list of alpha encrypted bits
    #0=< x =< 2^alpha-1 < p  , p prime
    bits_x=[]  #encrypted bit representation of x
    for i in range(alpha):
        #f.write("Computing bit "+str(i))
        coeffs_i=coeffs_Pbit_i(i=i,p=p,alpha=alpha)
        bits_x.append(compute_Pbit_i(x=x,p=p,coeffs_i=coeffs_i,HE=HE))
    return bits_x

def l1_norm(a_enc,a_enc_bits,b,b_bits,HE,alpha):
    #a_enc : encrypted vector a (list of Ctxt where each Ctxt is an encrypted coefficient of a)
    #a_enc : encrypted bits of each elt of a (list of lists of Ctxt)
    #same for b and b_bits 
    res=HE.encrypt(PyPtxt([0], HE))
    c_2=HE.encrypt(PyPtxt([2], HE))
    for i in range(len(b)):
        iss=is_smaller_fast1(b_bits[i],a_enc_bits[i],HE,alpha)
        tmp=(b[i]-a_enc[i])*iss*c_2
        tmp+=a_enc[i]
        tmp=tmp-b[i]
        res+=tmp
    return res

def dist(q_enc,q_bits_enc,X_train,HE,alpha):
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
    n=len(X_train)
    for i in range(n):
        #encrypt each elt of X_train[i] 
        b_enc=[HE.encrypt(PyPtxt([elt], HE)) for elt in X_train[i]]
        #also encrypt each elt of X_train[i] as a list of encrypted bits
        b_bits_enc=[encrypt_as_bits(elt,alpha,HE) for elt in X_train[i]]
        #compute dist(q,X_train[i])
        dist=l1_norm(q_enc,q_bits_enc,b_enc,b_bits_enc,HE,alpha)
        distances.append(dist)
    return distances

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":17,      "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":50,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}  

f.write("  Running KeyGen with params:")
f.write("\n")
f.write(str(KEYGEN_PARAMS))
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
f.write("  KeyGen completed in "+str(end-start)+" sec." )
f.write("\n")
f.write("\n")
f.flush()

filename="test_distance.txt"
f = open(filename, "a")

#parameters
alpha=4
p=17

#input data
q=[3,4,2]
X1=[0,3,1]

#encrypt q
q_enc=[HE.encrypt(PyPtxt([elt], HE) ) for elt in q]
q_bits_enc=[encrypt_as_bits(elt,alpha,HE,f) for elt in q]

start1=time.time()
distances=dist(q_enc,q_bits_enc,X1,HE,alpha)
end1=time.time()
f.write(str(end1-start1)+" sec to compute distances." )
f.write("\n")
f.write("\n")
f.flush()

start2=time.time()
distances_bit=[convert_to_bits(x,p,alpha,HE,f) for x in distances]
end2=time.time()
f.write(str(end2-start2)+" sec to convert distances to bits." )
f.write("\n")
f.flush()