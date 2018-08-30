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
def Psqrt(x,p,HE,f):
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
        f.write("l2 : "+str(l2))
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[]
        f.write("Computing coefficients of Psqrt") 
        f.write("\n")
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

#For a given number of bits alpha, this dict gives the smallest prime number greater than 2^alpha-1
prime_dict={4:17, 5:37, 6:67, 7:131, 8:257, 9:521, 10:1031, 11:2053, 12:4099, 13:8209}

L=30
p=17
filename="Psqrt_"+str(L)+"_"+str(p)+".txt"
f = open(filename, "a")


start = time.time()
HE = Pyfhel()
#Generate key
KEYGEN_PARAMS={ "p":p,   "r":1,
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
f.write("p="+str(p))
f.write("\n")
n=8
x=HE.encrypt(PyPtxt([n], HE))
f.write("x="+str(HE.decrypt(x)))
f.write("\n")
f.flush()

start = time.time()
result=Psqrt(x,p,HE,f)
decrypted_res=HE.decrypt(result)
f.write("floor(sqrt("+str(n)+")) : "+str(decrypted_res))
f.write("\n")
end=time.time()
f.write(str(end-start)+" sec." )
f.write("\n")
f.flush()