import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import math
import numpy as np
from random import randint

def encrypt_as_bits(x,alpha,HE):
    #takes in input a plaintext integer x =< 2^alpha -1
    #returns a list of the encrypted bits of x
    a='{0:0'+str(alpha)+'b}'
    x_bits=[int(i) for i in list(a.format(x))]
    x_bits_enc=[]
    for i in x_bits:
        x_bits_enc.append(HE.encrypt(PyPtxt([i], HE)))
    return x_bits_enc
    
def is_smaller(x_bits,y_bits,HE,alpha):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                       
        same_bit.append(HE.encrypt(PyPtxt([1], HE))-((x_bits[i]-y_bits[i])**2))
        tmp=HE.encrypt(PyPtxt([1], HE))
        for j in range(i+1):
            tmp*=same_bit[j]
        same_prefix.append(tmp)
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(HE.encrypt(PyPtxt([1], HE))-y_bits[i])*x_bits[i]*same_prefix[i]
    return res

##1st attempt to optimize is_smaller (using numpy arrays)
def is_smaller_fast1(x_bits,y_bits,HE,alpha):
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
    #r : Random number between 0 and n
    r=randint(0, n)
    r=int(math.floor((r**(1/float(deg)))))
    if r>((2**alpha) -1) : #NB : x=< 2**alpha -1 so if r>2**alpha-1, then r>x
        c_0=HE.encrypt(PyPtxt([0], HE))
        return c_0
    else :
        #encrypt r as a list of bits
        r_bits_enc=encrypt_as_bits(r,alpha,HE)
        #compare r_bits and x_bits
        return is_smaller(x_bits,r_bits_enc,HE,alpha=alpha)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha):
    #Takes in input a list of integers (each integer is a list of encrypted bits)
    #n=size of the vector input
    #alpha=number of bits on which each elt of the vector is encoded
    #deg is the degree of the moment to compute (deg=1 : average, deg=2 : second order moment)
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Returns an approximation of the statistical function (ie : average, 2nd order moment..) computed on the integer list

    #Initialize
    L=2**alpha
    c=int(math.ceil((L**deg)/float(n)))
    a=[]
    res=HE.encrypt(PyPtxt([0], HE))
    for i in range((c*n)):    
        tmp=int(math.floor(i/c)) 
        a.append(coinToss(list_x_bits[tmp],c*n,HE,deg=deg,alpha=alpha))
        res+=a[i]
    return res

def bezout(a, b):
    #computes (u,v,gcd) st a*u + b*v = gdc(a,b)
    if a == 0 and b == 0: return (0, 0, 0)
    if b == 0: return (a/abs(a), 0, abs(a))
    (u, v, gdc) = bezout(b, a%b)
    return (v, (u - v*(a/b)), gdc)
def inv_modulo(x, p):
    #Computes y in [p] st x*y=1 mod p
    (u, _, gdc) = bezout(x, p)
    if gdc == 1: return u%abs(p)
    else: raise Exception("%s et %s are not mutually prime" % (x, p))
        
def convert_to_bits(x,p,alpha,HE):
    def coeffs_Pbit_i(i,p,alpha):
        #Returns the coefficients ri that will help compute the polynomial P_bit that interpolates the function f:x-->bit_i(x) on [p]
        #alpha : nb of bits
        #0=< 2^alpha-1 < p, p prime
        #0=< i =< alpha
        l1=range(0,p)
        a='{0:0'+str(alpha)+'b}'
        l2=[int(list(a.format(x))[i]) for x in l1]
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
        coeffs_i=coeffs_Pbit_i(i=i,p=p,alpha=alpha)
        bits_x.append(compute_Pbit_i(x=x,p=p,coeffs_i=coeffs_i,HE=HE))
    return bits_x

def Psqrt(x,p,HE):
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
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
    coeffs=coeffs_Psqrt(p)
    #x encrypted as a single Ctxt
    #0=< x =< p  , p prime
    res=HE.encrypt(PyPtxt([0], HE))
    for i in range(0,p) :
        if coeffs[i]!=0:
            tmp=HE.encrypt(PyPtxt([coeffs[i]], HE))     
            for j in range(p):
                if i!=j:
                    tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            res+=tmp
    return res

def phi(x):
    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0

def k_smallest_values(list_d_bits,p,k,HE,alpha):
    #Takes in input a list of data (each encrypted as a list of bits)
    #a prime p such that each datapoint 0=< d =< sqrt(p)
    n=len(list_d_bits)
    #Compute average, 2nd order moment and std
    avg=probabilisticAverage(list_d_bits,n,HE,1,alpha=alpha) #L=sqrt(p) ?? donc alpha = log2(sqrt(p) ?????
    second_moment=probabilisticAverage(list_d_bits,n,HE,2,alpha=alpha)
    A=(avg**2)+second_moment
    std=Psqrt(A,p,HE)
    #Compute threshold
    phi_=HE.encrypt(PyPtxt([int(round(1/phi(float(k/n)/100),0))], HE))
    T=avg+phi_*std
    T_bits=convert_to_bits(T,p,alpha,HE)
    res=[]
    for i in range(n):
        res.append(is_smaller(T_bits,list_d_bits[i],HE,alpha=alpha))
    return res

def l1_norm(a_enc,a_enc_bits,b,b_bits,HE,alpha):
    #a_enc : encrypted vector a (list of Ctxt where each Ctxt is an encrypted coefficient of a)
    #a_enc : encrypted bits of each elt of a (list of lists of Ctxt)
    #same for b and b_bits 
    p_0=PyPtxt([0], HE)
    res=HE.encrypt(p_0)
    p_2=PyPtxt([2], HE)
    c_2=HE.encrypt(p_2)
    for i in range(len(b)):
        iss=is_smaller(b_bits[i],a_enc_bits[i],HE,alpha=alpha)
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
        dist=l1_norm(q_enc,q_bits_enc,b_enc,b_bits_enc,HE,alpha=alpha)
        distances.append(dist)
    return distances

def knn(q_enc,q_bits_enc,X_train,Y_train,HE_scheme,p,n,d,k,alpha,a_class):
    #q_enc =(enc(q1), ,enc(qd)) : list of the encrypted components of q
    #q_bits=([[q1_bits]], ,[[qd_bits]]) : list of lists, where [[q1_bits]] is the list of each encrypted bit of q1
    #X_train : training set (list of rows, each row being a list itself)
    #Y_train : labels associated with X_train
    #n,d : dimensions of X_train (n : nb of rows, d : nb of columns)
    #k : nb of nearest neighbors to output
    #alpha : nb of bits recquired to encode the input data
    #a_class : nb of bits recquired to encode the number of classes (ex : if 2 classes, a_class=1)
    #p : prime number such that each value in X_train and q are between 0 and sqrt(p)/d
    #HE_scheme : scheme used for encryption (Pyfhel object)

    #Compute the distances (q to each row of X_train)
    distances=dist(q_enc,q_bits_enc,X_train,HE_scheme,alpha)
    distances_bit=[]
    for i in range(len(distances)):
        distances_bit.append(convert_to_bits(distances[i],p,alpha,HE_scheme))
    #Compute Xi (position of the k-nearest neighbours)
    XI=k_smallest_values(distances_bit,k,p,HE_scheme,alpha)
    #Multiply by the auxiliary data
    y_enc=[HE_scheme.encrypt(PyPtxt([elt], HE_scheme)) for elt in X_train[i]]
    res=np.multiply(np.asarray(XI),np.asarray(y_enc))
    return res