import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np
from joblib import Parallel, delayed
import multiprocessing

from pathos.multiprocessing import ProcessingPool as Pool


def encrypt_as_bits(x,alpha,HE,f):
    #takes in input a plaintext integer x =< 2^alpha -1
    #returns a list of the encrypted bits of x
    a='{0:0'+str(alpha)+'b}'
    x_bits=[int(i) for i in list(a.format(x))]
    x_bits_enc=[]
    f.write("Encrypting "+str(x)+" in bits "+str(x_bits))
    f.write("\n")
    for i in x_bits:
        x_bits_enc.append(HE.encrypt(PyPtxt([i], HE)))
    return x_bits_enc

def is_smaller(x_bits,y_bits,HE,alpha):
    #takes in input 2 encrypted integers given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1) )
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

##1st attempt to optimize computation (using numpy arrays)
def is_smaller_fast1(x_bits,y_bits,HE,alpha):
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_bit =np.subtract(np.asarray(x_bits),np.asarray(y_bits))**2
    same_bit=np.subtract(np.asarray([c_1.copy(c_1) for i in range(alpha)]),same_bit)
    same_prefix=np.asarray([c_1.copy(c_1)]+[np.prod(same_bit[0:i+1]) for i in range(alpha-1)])
    to_sum=np.multiply(same_prefix,np.multiply(np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),np.asarray(y_bits)),np.asarray(x_bits)))
    res = np.sum(to_sum)
    return res


##2nd attempt (using joblib : doesn't work because the objects are not serializable)
class Computable1:
    def __init__(self,HE_scheme):
        self.HE = HE_scheme
    def f1(self, x, y):
        return self.HE.encrypt(PyPtxt([1], self.HE)) -((x-y)**2)

def is_smaller_fast2(x_bits,y_bits,HE,alpha):
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
    same_bit = Parallel(n_jobs=num_cores-1)(delayed(Computable1.f1)(x_bits[i], y_bits[i]) for i in range(alpha))
    same_prefix += Parallel(n_jobs=num_cores-1)(delayed(product)(same_bit, i) for i in range(alpha))
    to_sum=Parallel(n_jobs=num_cores-1)(delayed(lambda j: (HE.encrypt(PyPtxt([1], HE)) - y_bits[j]) * x_bits[j] * same_prefix[j])(i) for i in range(alpha))
    res = somme(to_sum, len(to_sum))
    return res

##3rd attempt (using pathos)
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
class Computable2:
    def __init__(self,HE_scheme):
        self.HE = HE_scheme
    def f1(self,x,y):
        return HE.encrypt(PyPtxt([1], HE))-((x-y)**2) 
    def f2(self,x,y,same_pref):
        return (HE.encrypt(PyPtxt([1], HE)) - y) * x * same_pref
    def run(self,x,y,alpha):
        pool = Pool().map
        same_prefix=[HE.encrypt(PyPtxt([1], HE))]
        same_bit = pool(self.f1, x,y)
        for i in range(alpha):
            same_prefix.append(product(same_bit,i))
        to_sum=pool(self.f2,x,y,same_prefix)
        result=somme(to_sum,len(to_sum))
        return result
def is_smaller_fast3(x_bits,y_bits,HE,alpha):
    m=Computable2(HE)
    return m.f3(y,x,alpha)


#For a given number of bits alpha, this dict gives the smallest prime number greater than 2^alpha-1
prime_dict={4:17, 5:37, 6:67, 7:131, 8:257, 9:521, 10:1031, 11:2053, 12:4099, 13:8209}

L=50
filename="is_smaller_"+str(L)+".txt"
f = open(filename, "a")

for alpha in range(4,13):
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


    #Test is_smaller with 2 integers x and y
    x=7
    y=6
    f.write("alpha="+str(alpha))
    f.write("\n")
    f.write("Test is_smaller with integers "+str(x)+" and "+str(y)+".")
    f.write("\n")
    f.flush()

    #Encrypt x bit by bit
    start = time.time()
    x_bits_enc=encrypt_as_bits(x,alpha,HE,f)
    end=time.time()
    f.write(str(end-start)+" sec." )
    f.write("\n")
    f.flush()

    #Encrypt y bit by bit
    start = time.time()
    y_bits_enc=encrypt_as_bits(y,alpha,HE,f)
    end=time.time()
    f.write(str(end-start)+" sec." )
    f.write("\n")
    f.flush()


    #Compare x and y with parallelization
    #start = time.time()
    #result=is_smaller_fast3(x_bits_enc,y_bits_enc,HE,alpha)
    #end=time.time()
    #decrypted_res=HE.decrypt(result)
    #print("decrypted result : ",decrypted_res)
    #print(str(end-start)+" sec." )

    #Compare x and y without parallelization
    start = time.time()
    result=is_smaller(x_bits_enc,y_bits_enc,HE,alpha)
    end=time.time()
    decrypted_res=HE.decrypt(result)
    f.write("decrypted result : "+str(decrypted_res))
    f.write("\n")
    f.write(str(end-start)+" sec." )
    f.write("\n")
    f.flush()

    #Compare x and y with np.arrays
    start = time.time()
    result=is_smaller_fast1(x_bits_enc,y_bits_enc,HE,alpha)
    end=time.time()
    decrypted_res=HE.decrypt(result)
    f.write("decrypted result : "+str(decrypted_res))
    f.write("\n")
    f.write(str(end-start)+" sec." )
    f.write("\n")
    f.write("\n")
    f.flush()
f.close()