import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np
from joblib import Parallel, delayed
import multiprocessing

def encrypt_as_bits(x,alpha,HE):
    #takes in input a plaintext integer x =< 2^alpha -1
    #returns a list of the encrypted bits of x
    a='{0:0'+str(alpha)+'b}'
    x_bits=[int(i) for i in list(a.format(x))]
    x_bits_enc=[]
    print("Encrypting "+str(x)+" in bits ",x_bits)
    for i in x_bits:
        x_bits_enc.append(HE.encrypt(PyPtxt([i], HE)))
    return x_bits_enc

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
        for j in range(i+1):
            #print("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        #print("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(HE.encrypt(PyPtxt([1], HE))-y_bits[i])*x_bits[i]*same_prefix[i]
            #print("res : ",HE.decrypt(res))
    return res
class Computable:
    def __init__(self,HE_scheme):
        self.HE = HE_scheme
    def f1(self, x, y):
        return self.HE.encrypt(PyPtxt([1], self.HE)) -((x-y)**2)

def is_smaller_fast(x_bits,y_bits,HE,alpha,n=1000):
    def product(l, i):
        res = 1
        for j in range(i+1):
            res *= l[j]
        return res
    def somme(l, i):
        res = 0
        for j in range(i):
            res += l[j]
        return res
    num_cores = multiprocessing.cpu_count() #number of cores
    print("number of cores : ",num_cores)
    same_prefix=[HE.encrypt(PyPtxt([1], HE))]

    same_bit = Parallel(n_jobs=num_cores-1)(delayed(Computable.f1)(x_bits[i], y_bits[i]) for i in range(alpha))
    same_prefix += Parallel(n_jobs=num_cores-1)(delayed(product)(same_bit, i) for i in range(alpha))
    to_sum=Parallel(n_jobs=num_cores-1)(delayed(lambda j: (HE.encrypt(PyPtxt([1], HE)) - y_bits[j]) * x_bits[j] * same_prefix[j])(i) for i in range(alpha))
    res = somme(to_sum, len(to_sum))
    return res

def is_smaller_fast2(x_bits,y_bits,HE,alpha,n=1000):
    same_bit =np.subtract(np.asarray(x_bits),np.asarray(y_bits))
    same_bit=same_bit**2
    same_bit=np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),same_bit)
    for i in range(alpha):
        print("samebit("+str(i)+") : ",HE.decrypt(same_bit[i]))
    same_prefix=[HE.encrypt(PyPtxt([1], HE))]
    same_prefix=same_prefix+[np.prod(same_bit[0:i+1]) for i in range(alpha-1)]
    same_prefix=np.asarray(same_prefix)
    for i in range(alpha):
        print("sameprefix("+str(i)+") : ",HE.decrypt(same_prefix[i]))
    to_sum=np.multiply(same_prefix,np.multiply(np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),np.asarray(x_bits)),np.asarray(x_bits)))
    for i in range(alpha):
        print("sameprefix("+str(i)+") : ",HE.decrypt(to_sum[i]))
    res = np.sum(to_sum)
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


#Test is_smaller with 2 integers x and y
x=8
y=7
alpha=4
print("Test is_smaller with integers "+str(x)+" and "+str(y)+".")

#Encrypt x bit by bit
start = time.time()
x_bits_enc=encrypt_as_bits(x,alpha,HE)
end=time.time()
print(str(end-start)+" sec." )

#Encrypt y bit by bit
start = time.time()
y_bits_enc=encrypt_as_bits(y,alpha,HE)
end=time.time()
print(str(end-start)+" sec." )


#Compare x and y with parallelization
start = time.time()
result=is_smaller_fast2(x_bits_enc,y_bits_enc,HE,alpha)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )

#Compare x and y without parallelization
start = time.time()
result=is_smaller(x_bits_enc,y_bits_enc,HE,alpha)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)
end=time.time()
print(str(end-start)+" sec." )