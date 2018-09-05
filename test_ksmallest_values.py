import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import time
import math
import numpy as np
from random import randint

     
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
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_bit =np.subtract(np.asarray(x_bits),np.asarray(y_bits))**2
    same_bit=np.subtract(np.asarray([c_1.copy(c_1) for i in range(alpha)]),same_bit)
    same_prefix=np.asarray([c_1.copy(c_1)]+[np.prod(same_bit[0:i+1]) for i in range(alpha-1)])
    to_sum=np.multiply(same_prefix,np.multiply(np.subtract(np.asarray([HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]),np.asarray(y_bits)),np.asarray(x_bits)))
    res = np.sum(to_sum)
    return res

def coinToss(x_bits,n,HE,deg,alpha):
#Takes in input an integer n, and an encrypted number 0=< x_bits <n as a list of alpha bits
#generates a random number r between 0 and n  (potentially drawn from a distribution D)
#Returns an encrypted bit b=[1] if r^(1/deg)<x (ie : with probability x/n) otherwise [0]
    #print("Random number between 0 and "+str(n))
    r=randint(0, n)
    r=int(math.floor((r**(1/float(deg)))))
    print(r)
    if r>((2**alpha) -1) : #rq : x=< 2**alpha -1 so if r>2**alpha-1, then r>x
        c_0=HE.encrypt(PyPtxt([0], HE))
        return c_0
    else :
        #encrypt r as a list of bits
        r_bits_enc=encrypt_as_bits(r,alpha,HE,f)
        #compare r_bits and x_bits
        return is_smaller(x_bits,r_bits_enc,HE,alpha=alpha)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha,f):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #alpha=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute (deg=1 : average, deg=2 : second order moment)
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list
    
    #Initialize
    L=2**alpha
    c=int(math.ceil((L**deg)/float(n)))
    res=HE.encrypt(PyPtxt([0], HE))
    f.write("c*n="+str(c*n))
    f.write("\n")
    for i in range((c*n)):       #rq : pour L=8 et n=3, c=3 et c*n=9 (environ 440sec)
        tmp=int(math.floor(i/float(c)))    #(rq le dernier i sera c*n-1 donc le dernier tmp sera n-1)
        tmp=coinToss(list_x_bits[tmp],c*n,HE,deg=deg,alpha=alpha)
        res+=tmp  #peut etre pas besoin d'une liste (sommer directement les elts dans res)
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
    def coeffs_Pbit_i(i,p,alpha):
        #Returns the coefficients ri that will help compute the polynomial P_bit that interpolates the function f:x-->bit_i(x) on [p]
        #alpha : nb of bits
        #0=< 2^alpha-1 < p, p prime
        #0=< i =< alpha
        l1=range(0,p)
        a='{0:0'+str(alpha)+'b}'
        l2=[int(list(a.format(x))[i]) for x in l1]
        #print("l2 : ",l2)
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
        f.write("Computing bit "+str(i))
        f.write("\n")
        f.flush()
        coeffs_i=coeffs_Pbit_i(i=i,p=p,alpha=alpha)
        bits_x.append(compute_Pbit_i(x=x,p=p,coeffs_i=coeffs_i,HE=HE))
    return bits_x

def Psqrt(x,p,HE,f):
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
        #print("l2 : ",l2)
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[] 
        for i in range(p):
            num=l2[i]
            den=1
            for j in range(p):
                if i!=j:
                    den*=i-j
            tmp=(num*inv_modulo(den,p))%p
            r.append(int(tmp))
        return r
    f.write("Computing coefficients of Psqrt")
    f.write("\n")
    f.flush()
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

def phi(x):
    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0

def k_smallest_values(list_d_bits,p,k,HE,alpha,f):
    #Takes in input a list of data (each encrypted as a list of bits)
    #a prime p such that each datapoint 0=< d =< sqrt(p)
    n=len(list_d_bits)
    #Compute average, 2nd order moment and std
    f.write("\n")
    f.write("Compute average")
    f.write("\n")
    avg=probabilisticAverage(list_d_bits,n,HE,1,alpha=alpha,f=f) #L=sqrt(p) ?? donc alpha = log2(sqrt(p) ?????
    f.write("average : "+str(HE.decrypt(avg)))
    f.write("\n")
    f.write("\n")
    f.flush()
    f.write("Compute second_moment")
    f.write("\n")
    second_moment=probabilisticAverage(list_d_bits,n,HE,2,alpha=alpha,f=f)
    f.write("\n")
    f.write("second_moment : "+str(HE.decrypt(second_moment)))
    f.write("\n")
    f.write("\n")
    f.flush()
    A=(avg**2)+second_moment
    f.write("A : "+str(HE.decrypt(A)))
    f.write("\n")
    f.write("Compute std")
    f.write("\n")
    f.flush()
    std=Psqrt(A,p,HE,f)
    f.write("std : "+str(HE.decrypt(std)))
    f.write("\n")
    f.flush()
    #Compute threshold
    f.write("Compute threshold and convert to bits")
    f.write("\n")
    phi_=HE.encrypt(PyPtxt([int(round(1/phi(float(k/n)/100),0))], HE))
    f.write("\n")
    f.write(str(int(round(1/phi(float(k/n)/100),0))))
    f.write("\n")
    f.write ("phi : "+str(HE.decrypt(phi_)))
    f.write("\n")
    f.flush()
    T=avg+phi_*std
    f.write("threshold : "+str(HE.decrypt(T)))
    f.write("\n")
    f.flush()
    T_bits=convert_to_bits(T,p,alpha,HE,f)
    f.write("threshold bit by bit : ")
    f.write("\n")
    f.flush()
    for bit in T_bits :
        f.write(str(HE.decrypt(bit)))
        f.write("\n")
        f.flush()
    res=[]
    for i in range(n):
        res.append(is_smaller(T_bits,list_d_bits[i],HE,alpha=alpha))
        f.write("dist("+str(i)+") : "+str(HE.decrypt(res[i])))
        f.write("\n")
        f.flush()
    return res

#params
p=37
L=50
t=1
alpha=5
k=2

filename="ksv_alpha"+str(alpha)+".txt"
f = open(filename, "a")

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":p,      "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":L,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}                
f.write("\n")
f.write("  Running KeyGen with params:")
f.write("\n")
f.write(str(KEYGEN_PARAMS))
f.write("\n")
f.flush()
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
f.write("  KeyGen completed in "+str(end-start)+" sec." )
f.write("\n")
f.flush()

#Create a random list of distances and encrypt them bit by bit
#dist=[0, 3, 2, 2, 2, 2, 3, 4, 0, 2, 0, 0, 0, 0, 1, 4, 2, 1, 0, 0, 0, 2, 2, 2, 4, 1, 1, 2, 1, 0, 0, 1, 0, 2, 0, 0, 1, 1, 2, 0, 2, 1, 3, 4, 1, 3, 2, 0, 1, 3, 4, 3, 1, 3, 3, 2, 1, 3, 1, 4, 0, 2, 2, 0, 3, 2, 1, 0, 0, 2, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 3, 2, 3, 2, 4, 4, 2, 4, 2, 3, 4, 3, 3, 3, 1, 2, 3, 2, 3, 2]
dist=[6, 4, 6, 3, 6, 5, 5, 0, 6, 4, 3, 2, 1, 1, 3, 6, 1, 1, 0, 4, 0, 2, 2, 4, 0, 0, 3, 4, 5, 4, 2, 6, 6, 1, 4, 3, 3, 6, 4, 2, 0, 3, 1, 5, 0, 5, 1, 3, 4, 3, 0, 3, 3, 1, 5, 4, 4, 3, 5, 1, 1, 6, 4, 6, 2, 4, 6, 4, 1, 5, 1, 5, 0, 6, 4, 2, 3, 1, 4, 6, 6, 3, 4, 0, 2, 1, 5, 5, 2, 5, 2, 6, 0, 4, 2, 4, 1, 5, 5, 0]
dist_bits=[encrypt_as_bits(d,alpha,HE,f) for d in dist]

#Return the position of the k smallest values of the list
start = time.time()
result=k_smallest_values(dist_bits,p,k,HE,alpha,f)
decrypted_res=[HE.decrypt(res) for res in result]
f.write("decrypted result : "+str(decrypted_res))
f.write("\n")
end=time.time()
f.write(str(end-start)+" sec." )
f.write("\n")
f.close()