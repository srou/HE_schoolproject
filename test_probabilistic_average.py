import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np
from random import randint
import argparse

#In this file, we are testing the function probabilisticAverage for different values of L, alpha
# and n (length of the list which we want to compute the average of)
parser=argparse.ArgumentParser()
parser.add_argument("L",type=int)
parser.add_argument("alpha",type=int)
parser.add_argument("n",type=int)
args=parser.parse_args()

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

def is_smaller(x_bits,y_bits,HE,alpha):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    #print("Initisalisation")
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        same_bit.append(HE.encrypt(PyPtxt([1], HE))-((x_bits[i]-y_bits[i])**2))
        tmp=HE.encrypt(PyPtxt([1], HE))
        for j in range(i+1):
            #print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        #print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(HE.encrypt(PyPtxt([1], HE))-y_bits[i])*x_bits[i]*same_prefix[i]
            #print("res : ",HE.decrypt(res))
    return res

def is_smaller_fast1(x_bits,y_bits,HE,alpha):
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_bit =np.subtract(np.asarray(x_bits),np.asarray(y_bits))**2
    same_bit=np.subtract(np.asarray([c_1.copy(c_1) for i in range(alpha)]),same_bit)
    same_prefix=np.asarray([c_1.copy(c_1)]+[np.prod(same_bit[0:i+1]) for i in range(alpha-1)])
    to_sum=np.multiply(same_prefix,np.multiply(np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),np.asarray(y_bits)),np.asarray(x_bits)))
    res = np.sum(to_sum)
    return res

def coinToss(x_bits,n,HE,deg,alpha,f):
#Takes in input an integer n, and an encrypted number 0=< x_bits <n as a list of alpha bits
#generates a random number r between 0 and n  (potentially drawn from a distribution D)
#Returns an encrypted bit b=[1] if r^(1/deg)<x (ie : with probability x/n) otherwise [0]
    #print("Random number between 0 and "+str(n))
    r=randint(0, n)
    #print("r : ",r)
    r=int(math.floor((r**(1/float(deg)))))
    if r>((2**alpha) -1) : #rq : x=< 2**alpha -1 so if r>2**alpha-1, then r>x
        c_0=HE.encrypt(PyPtxt([0], HE))
        return c_0
    else :
        #encrypt r as a list of bits
        r_bits_enc=encrypt_as_bits(r,alpha,HE,f=f)
        #compare r_bits and x_bits
        return is_smaller_fast1(x_bits,r_bits_enc,HE,alpha=alpha)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha,f):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #alpha=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute (deg=1 : average, deg=2 : second order moment)
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list
    
    #Initialize
    L=2**alpha
    f.write("L="+str(L))
    f.write("\n")
    f.flush()
    c=int(math.ceil((L**deg)/float(n)))
    f.write("c="+str(c))
    f.write("\n")
    f.flush()
    res=HE.encrypt(PyPtxt([0], HE))
    f.write("c*n="+str(c*n))
    f.write("\n")
    f.flush()
    for i in range((c*n)):       #rq : pour L=8 et n=3, c=3 et c*n=9 (environ 440sec)
        tmp=int(math.floor(i/float(c)))    #(rq le dernier i sera c*n-1 donc le dernier tmp sera n-1)
        #print("")
        #print("tmp="+str(tmp))
        #print("")
        tmp=coinToss(list_x_bits[tmp],c*n,HE,deg=deg,alpha=alpha,f=f)
        #print("result of the coin toss : ",HE.decrypt(tmp))
        res+=tmp  #peut etre pas besoin d'une liste (sommer directement les elts dans res)
    return res

def probabilisticAverage_fast(list_x_bits,n,HE,deg,alpha,f):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #alpha=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute (deg=1 : average, deg=2 : second order moment)
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list
    
    #Initialize
    L=2**alpha
    f.write("L="+str(L))
    f.write("\n")
    f.flush()
    c=int(math.ceil((L**deg)/float(n)))
    f.write("c="+str(c))
    f.write("\n")
    f.flush()
    res=HE.encrypt(PyPtxt([0], HE))
    f.write("c*n="+str(c*n))
    f.write("\n")
    f.flush()
    list_elts=np.asarray([list_x_bits[int(math.floor(i/float(c)))] for i in range(c*n)])
    f.write("len(list_elts)"+str(len(list_elts)))
    f.write("\n")
    f.flush()
    def fct(x):
        return coinToss(x,c*n,HE,deg=deg,alpha=alpha,f=f)
    def array_map(x):
        return np.array(list(map(fct, x)))
    #vf=np.vectorize(f)
    #print("to_sum")
    #to_sum=vf(list_elts)
    to_sum=array_map(list_elts)
    #print ("res")
    res = np.sum(to_sum)
    return res

#For a given number of bits alpha, this dict gives the smallest prime number greater than 2^alpha-1
prime_dict={4:17, 5:37, 6:67, 7:131, 8:257, 9:521, 10:1031, 11:2053, 12:4099, 13:8209}

L=args.L
alpha=args.alpha
n=args.n
filename="average_"+str(L)+"_"+str(alpha)+"_"+str(n)+".txt"
f = open(filename, "a")

#Generate Key
start = time.time()
HE = Pyfhel()
KEYGEN_PARAMS={ "p":prime_dict[alpha],   "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":L,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}  
f.write("  Running KeyGen with params:")
f.write("\n")
f.write(str(KEYGEN_PARAMS))
f.flush()
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
f.write("  KeyGen completed in "+str(end-start)+" sec." )
f.write("\n")
f.flush()

#list of n numbers which we want to compute the average
list_nb=[]
for i in range(n):
    list_nb.append(randint(0,(2**alpha)-1))
list_x_bits=[encrypt_as_bits(x,alpha,HE,f) for x in list_nb]

#Compute the probabilistic average of the list of int
#f.write("\n")
#f.write("\n")
#f.write("Compute fast Average of "+str(list_nb))
#f.write("\n")
#f.write("\n")
#f.flush()
#start = time.time()
#result=probabilisticAverage_fast(list_x_bits,len(list_nb),HE,1,alpha,filename)
#end=time.time()
#decrypted_res=HE.decrypt(result)
#print("decrypted result : "+str(decrypted_res))
#f.write("\n")
#print(str(end-start)+" sec." )
#f.write("\n")
#f.flush()

#Compute the probabilistic average of the list of int
f.write("\n")
f.write("\n")
print("Compute Average of "+str(list_nb))
f.write("\n")
f.write("\n")
f.flush()
start = time.time()
result=probabilisticAverage(list_x_bits,len(list_nb),HE,1,alpha,filename)
end=time.time()
decrypted_res=HE.decrypt(result)
print("decrypted result : "+str(decrypted_res))
f.write("\n")
print(str(end-start)+" sec." )
f.write("\n")
f.flush()

#Compute the 2nd order moment of the list of int
f.write("\n")
f.write("\n")
print("Compute 2nd moment order of "+str(list_nb))
f.write("\n")
f.write("\n")
f.flush()
start = time.time()
result=probabilisticAverage(list_x_bits,len(list_nb),HE,2,alpha,filename)
end=time.time()
decrypted_res=HE.decrypt(result)
f.write("decrypted result : "+str(decrypted_res))
f.write("\n")
print(str(end-start)+" sec." )
f.write("\n")
f.flush()