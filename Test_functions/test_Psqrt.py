import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np

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
def Psqrt(x,p,HE):
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
        print("values : "+str(l2))
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[]
        print("Computing coefficients of Psqrt") 
        for i in range(p):
            num=l2[i]
            den=1
            for j in range(p):
                if i!=j:
                    den*=i-j
            tmp=(num*inv_modulo(den,p))%p
            r.append(int(tmp))
        return r
    coeffs=coeffs_Psqrt(p)
    #x encrypted as a single Ctxt
    #0=< x =< p  , p prime
    res=HE.encrypt(PyPtxt([0], HE))
    for i in range(0,p) :
        if coeffs[i]!=0:
            tmp=HE.encrypt(PyPtxt([coeffs[i]], HE))     
            for j in range(p):
                if i!=j:
                    #print("j ",j) 
                    #print("x-"+str(j)+" : ",HE.decrypt(x-HE.encrypt(PyPtxt([j], HE))))
                    tmp*=(x-HE.encrypt(PyPtxt([j], HE))) # tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            #print 'coeffs[i]',type(coeffs[i]),coeffs[i]
            #print "tmp",type(tmp),HE.decrypt(tmp)
            #print("")
            res+=tmp
    return res

def Psqrt2(x,p,HE,f):
    #attempt to improve computation using the polynomialMult method
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
        f.write("l2 : "+str(l2))
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[]
        f.write("\n")
        f.write("Computing coefficients of Psqrt") 
        f.write("\n")
        f.flush()
        for i in range(p):
            num=l2[i]
            den=1
            for j in range(p):
                if i!=j:
                    den*=i-j
            tmp=(num*inv_modulo(den,p))%p
            r.append(int(tmp))
        return r
    coeffs=coeffs_Psqrt(p)
    #x encrypted as a single Ctxt
    #0=< x =< p  , p prime
    coeffs_ctxt=[]
    for i in range(p):
        coeffs_ctxt.append(HE.encrypt(PyPtxt([coeffs[i]], HE)))
    res=x.polynomialMult(coeffs_ctxt)
    return res

#For a given number of bits alpha, this dict gives the smallest prime number greater than 2^alpha-1
prime_dict={4:17, 5:37, 6:67, 7:131, 8:257, 9:521, 10:1031, 11:2053, 12:4099, 13:8209}

L=40
p=17
alpha=4
#filename="Psqrt_"+str(L)+"_"+str(p)+".txt"
#f = open(filename, "a")


#Generate Key
start = time.time()
HE = Pyfhel()
KEYGEN_PARAMS={ "p":prime_dict[alpha],   "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":L,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}  
print("  Running KeyGen with params:")
print(str(KEYGEN_PARAMS))
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )
print("")

#preliminary test
#start = time.time()
#a=HE.encrypt(PyPtxt([4], HE))
#end=time.time()
#f.write("encrypts an int in : "+str(end-start)+" sec." )
#f.write("\n")
#f.flush()
#b=HE.encrypt(PyPtxt([6], HE))
#f.write("4-6"+str(HE.decrypt(a-b)))
#f.write("\n")
#f.flush()


#Compute floor(sqrt(x))
p=KEYGEN_PARAMS["p"]
print("p="+str(p))
n=8
x=HE.encrypt(PyPtxt([n], HE))
print("x="+str(HE.decrypt(x)))

start = time.time()
result=Psqrt(x,p,HE)
decrypted_res=HE.decrypt(result)
print("floor(sqrt("+str(n)+")) : "+str(decrypted_res))
end=time.time()
print(str(end-start)+" sec." )
print("")