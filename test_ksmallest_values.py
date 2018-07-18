import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np
from random import randint

## peut etre détailler ici abréviations pour simplifier les commentaires
#l_bits= integer(??) encrypted as a list of encrypted bits. Ex : 5 on 4 bits -> ([0],[1],[0],[1])
#input data are a list of l_bits (pas exactement car pas forcement integer)
     

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

def coinToss(x_bits,n,HE,deg=1,alpha=5):
#Takes in input an integer n, and an encrypted number 0=< x_bits <n as a list of alpha bits
#generates a random number r between 0 and n  (potentially drawn from a distribution D)
#Returns an encrypted bit b=[1] if r^(1/deg)<x (ie : with probability x/n) otherwise [0]
    print("Random number between 0 and "+str(n))
    r=randint(0, n)
    r=int(math.floor((r**(1/deg))))
    #exception : r cannot be larger than (2^alpha)-1, otherwise it cannot be encoded on the same number of bits as x_bits
    if r>(2**alpha)-1:
        r=(2**alpha)-1
    #encrypt r as a list of bits
    print("Encrypt "+str(r)+" as a list of bits.")
    a='{0:0'+str(alpha)+'b}'
    r_bits=[int(i) for i in list(a.format(r))] 
    print(r_bits)
    r_bits_enc=[]
    for i in r_bits:
        p=PyPtxt([i], HE)
        r_bits_enc.append(HE.encrypt(p))
    #compare r_bits and x_bits
    return is_smaller(x_bits,r_bits_enc,HE,alpha=alpha)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha=5):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #L=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list
    
    #Initialize
    L=2**alpha
    c=int(math.floor((L**deg)/n))  #peut etre pas +1
    a=[]  
    p_0=PyPtxt([0], HE)
    res=HE.encrypt(p_0)
    print("c*n="+str(c*n))
    for i in range((c*n)):       #rq : pour L=8 et n=3, c=3 et c*n=9 (environ 440sec)
        tmp=int(math.floor(i/c))    #(rq le dernier i sera c*n-1 donc le dernier tmp sera n-1)
        print("")
        print("tmp="+str(tmp))
        print("")
        a.append(coinToss(list_x_bits[tmp],c*n,HE,deg=deg,alpha=alpha))
        decrypted_res=HE.decrypt(a[i])
        print("result of the coin toss : ",decrypted_res)
        res+=a[i]  #peut etre pas besoin d'une liste (sommer directement les elts dans res)
    return res
def phi(t,mean,std,data_enc,n,HE,alpha):
    #Cumulative distribution function
    
    #Takes in input a float t between 0 and 1, a list of encrypted data, and the mean and std of this distribution
    
    p_0=PyPtxt([0], HE)
    res=HE.encrypt(p_0)
    cste=int((t*std) + mean) 
    print("Encrypt "+str(cste)+" as a list of bits.")
    a='{0:0'+str(alpha)+'b}'
    cste_bits=[int(i) for i in list(a.format(r))] 
    print(cste_bits)
    cste_bits_enc=[]
    for i in cste_bits:
        p=PyPtxt([i], HE)
        cste_bits_enc.append(HE.encrypt(p))

    for k in range(n):
        res+=is_smaller(cste_bits_enc,data_enc[k],HE,alpha=alpha)
    res=res*(1/n)
    return res
def P_bits(x,i,p,alpha):
    #x encrypted bit by bit (coded on alpha bits)
    #0=< x =< p
    #0=< i <alpha
    #returns [1] if the ith bit of x is 1, otherwise 0
    return 0
def P_sqrt(x,p):
    #returns sqrt(x) for an int x in [0,p]
    l1=range(0,p)
    l2=[math.sqrt(i) for i in l1]
    coeffs=np.polyfit(l1,l2,p)

    p_1=PyPtxt([1], HE)
    c_1=HE.encrypt(p_1)
    res=c_1*coeffs[0]
    for k in range(1,len(coeffs)):
        res+=coeffs[k]*(x**k)
    return res

def k_smallest_values(list_d_bits,p,HE,alpha=5):
    #Takes in input a list of data (each encrypted as a list of bits)
    #a prime p such that each datapoint 0=< d =< sqrt(p)
    n=len(list_d_bits)
    avg=probabilisticAverage(list_d_bits,n,HE,1,alpha=alpha) #L=sqrt(p) ?? donc alpha = log2(sqrt(p) ?????
    second_moment=avg=probabilisticAverage(list_d_bits,n,HE,2,alpha=alpha)
    A=avg**2+second_moment
    std=P_sqrt(A)     ## attention au bruit pour les polynomes de degré elevé
    T=avg+phi(k/n,avg,std,list_d_bits,n,HE,alpha)*std   # comment faire phi ???
    T_bits=             #comment trouver Pbits_i ???
    res=[]
    for i in range(n):
        res.append(is_smaller(T_bits,list_d_bits[i],HE,alpha=alpha))
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