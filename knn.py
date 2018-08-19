import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np
from random import randint

#test knn writing file

#with open("results_knn2.txt", "w") as f:
#    f.write("knn_results")
filename="results_knn10.txt"
f = open(filename, "a")

def encrypt_as_bits(x,alpha,HE,f=f):
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
    
def is_smaller(x_bits,y_bits,HE,alpha,n=1000,f=f):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #coded on alpha bits
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation of same_prefix and same_bit
    #f.write("Initisalisation")
    c_1=HE.encrypt(PyPtxt([1], HE))
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]
    for i in range(alpha):                        #min(alpha,int(math.floor(math.log(n))+1))):
        same_bit.append(HE.encrypt(PyPtxt([1], HE))-((x_bits[i]-y_bits[i])**2))
        tmp=HE.encrypt(PyPtxt([1], HE))
        for j in range(i+1):
            #f.write("same_bit : "+str(j),HE.decrypt(same_bit[j]))
            tmp*=same_bit[j]
        #f.write("tmp : ",HE.decrypt(tmp))
        same_prefix.append(tmp)
        if i>0:  #since the 1st term of the sum is already computed before the loop
            res+=(HE.encrypt(PyPtxt([1], HE))-y_bits[i])*x_bits[i]*same_prefix[i]
            #f.write("res : ",HE.decrypt(res))
    return res

def coinToss(x_bits,n,HE,deg,alpha,f=f):
#Takes in input an integer n, and an encrypted number 0=< x_bits <n as a list of alpha bits
#generates a random number r between 0 and n  (potentially drawn from a distribution D)
#Returns an encrypted bit b=[1] if r^(1/deg)<x (ie : with probability x/n) otherwise [0]
    #f.write("Random number between 0 and "+str(n))
    r=randint(0, n)
    f.write("r : "+str(r))
    f.write("\n")
    r=int(math.floor((r**(1/float(deg)))))
    f.write(r)
    if r>((2**alpha) -1) : #rq : x=< 2**alpha -1 so if r>2**alpha-1, then r>x
        c_0=HE.encrypt(PyPtxt([0], HE))
        return c_0
    else :
        #encrypt r as a list of bits
        r_bits_enc=encrypt_as_bits(r,alpha,HE,f)
        #compare r_bits and x_bits
        return is_smaller(x_bits,r_bits_enc,HE,alpha=alpha,f=f)

def probabilisticAverage(list_x_bits,n,HE,deg,alpha,f=f):
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
    c=int(math.ceil((L**deg)/float(n)))
    f.write("c="+str(c))
    f.write("\n")
    a=[]
    res=HE.encrypt(PyPtxt([0], HE))
    f.write("c*n="+str(c*n))
    f.write("\n")
    f.flush()
    for i in range((c*n)):       #rq : pour L=8 et n=3, c=3 et c*n=9 (environ 440sec)
        tmp=int(math.floor(i/c))    #(rq le dernier i sera c*n-1 donc le dernier tmp sera n-1)
        f.write("\n")
        f.write("\n")
        f.write("tmp="+str(tmp))
        f.write("\n")
        f.write("\n")
        f.flush()
        a.append(coinToss(list_x_bits[tmp],c*n,HE,deg=deg,alpha=alpha,f=f))
        #decrypted_res=HE.decrypt(a[i])
        #f.write("result of the coin toss : ",decrypted_res)
        res+=a[i]  #peut etre pas besoin d'une liste (sommer directement les elts dans res)
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
        
def convert_to_bits(x,p,alpha,HE,f=f):
    def coeffs_Pbit_i(i,p,alpha,f=f):
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

def Psqrt(x,p,HE):
    def coeffs_Psqrt(p):
        #Returns the coefficients ri that will help compute the polynomial P_sqrt that interpolates the function f:x-->floor(sqrt(x)) on [p]
        l1=range(0,p)
        l2=[int(math.floor(math.sqrt(i))) for i in l1]
        #f.write("l2 : ",l2)
        #find the coeffs ri (in Zp) that help construct the polynomial
        r=[]
        #f.write("Computing coefficients of Psqrt") 
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
                    #f.write("j ",j) 
                    #f.write("x-"+str(j)+" : ",HE.decrypt(x-HE.encrypt(PyPtxt([j], HE))))
                    tmp*=(x-HE.encrypt(PyPtxt([j], HE))) # tmp*=(x-HE.encrypt(PyPtxt([j], HE)))
            #f.write 'coeffs[i]',type(coeffs[i]),coeffs[i]
            #f.write "tmp",type(tmp),HE.decrypt(tmp)
            #f.write("")
            res+=tmp
    return res

def phi(x):
    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0

def k_smallest_values(list_d_bits,p,k,HE,alpha,f=f):
    #Takes in input a list of data (each encrypted as a list of bits)
    #a prime p such that each datapoint 0=< d =< sqrt(p)
    n=len(list_d_bits)
    #Compute average, 2nd order moment and std
    f.write("Compute average")
    f.write("\n")
    avg=probabilisticAverage(list_d_bits,n,HE,1,alpha=alpha) #L=sqrt(p) ?? donc alpha = log2(sqrt(p) ?????
    f.write("average : "+str(HE.decrypt(avg)))
    f.flush()
    f.write("\n")
    f.write("\n")
    f.write("Compute second_moment")
    second_moment=probabilisticAverage(list_d_bits,n,HE,2,alpha=alpha)
    f.flush()
    f.write("\n")
    f.write("\n")
    f.write("second_moment : "+str(HE.decrypt(second_moment)))
    f.flush()
    f.write("\n")
    A=(avg**2)+second_moment
    f.write("A : "+str(HE.decrypt(A)))
    f.flush()
    f.write("\n")
    f.write("Compute std")
    f.write("\n")
    std=Psqrt(A,p,HE)
    f.write("std : "+str(HE.decrypt(std)))
    f.flush()
    f.write("\n")
    #Compute threshold
    f.write("Compute threshold and convert to bits")
    f.write("\n")
    phi_=HE.encrypt(PyPtxt([int(round(1/phi(float(k/n)/100),0))], HE))
    f.write(int(round(1/phi(float(k/n)/100),0)))
    f.write ("phi : "+str(HE.decrypt(phi_)))
    f.flush()
    f.write("\n")
    T=avg+phi_*std
    f.write("threshold : "+str(HE.decrypt(T)))
    f.flush()
    f.write("\n")
    T_bits=convert_to_bits(T,p,alpha,HE)
    f.flush()
    f.write("threshold bit by bit : ")
    f.write("\n")
    for bit in T_bits :
        f.write(str(HE.decrypt(bit)))
        f.flush()
        f.write("\n")
    res=[]
    for i in range(n):
        res.append(is_smaller(T_bits,list_d_bits[i],HE,alpha=alpha))
        f.write("dist("+str(i)+") : "+str(HE.decrypt(res[i])))
        f.flush()
        f.write("\n")
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
        iss=is_smaller(b_bits[i],a_enc_bits[i],HE,alpha=alpha,n=1000)
        tmp=(b[i]-a_enc[i])*iss*c_2   ##peut etre besoin de copier c_2
        #f.write("tmp ",HE.decrypt(tmp))
        tmp+=a_enc[i]
        tmp=tmp-b[i]
        res+=tmp
    return res

def dist(q_enc,q_bits_enc,X_train,HE_scheme,alpha,f=f):
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
        b_bits_enc=[encrypt_as_bits(elt,alpha,HE,f) for elt in X_train[i]]
        #compute dist(q,X_train[i])
        dist=l1_norm(q_enc,q_bits_enc,b_enc,b_bits_enc,HE=HE_scheme,alpha=alpha)
        distances.append(dist)
    return distances

def knn(q_enc,q_bits_enc,X_train,Y_train,HE_scheme,p,n,d,k,alpha,a_class,file=f):
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

    f.write("Distances between q and elements of X_train : ")
    f.write("\n")
    start1 = time.time()
    distances=dist(q_enc,q_bits_enc,X_train,HE_scheme,alpha,f)
    f.write("len(distances"+str(len(distances)))
    f.write("\n")
    for res in distances :
        f.write(str(HE.decrypt(res)))
        f.flush()
    end1=time.time()
    f.write(str(end1-start1)+" sec to compute distances." )
    f.write("\n")
    f.write("\n")
    f.write("Convert distances to bits ")
    f.write("\n")
    start2 = time.time()
    distances_bit=[]
    for i in range(len(distances)):
        distances_bit.append(convert_to_bits(distances[i],p,alpha,HE,f))
        f.write("convert distance "+str(i))
        f.write("\n")
    end2=time.time()
    f.write(str(end2-start2)+" sec to convert distances to bits." )
    f.flush()
    f.write("\n")
    f.write("\n")
    f.write("\n")
    f.write("Compute Xi (position of the k-nearest neighbours) :")
    f.write("\n")
    start3 = time.time()
    XI=k_smallest_values(distances_bit,k,p,HE,alpha,f)
    end3=time.time()
    f.write(str(end3-start3)+" sec to compute the position of the k nearest neighbours." )
    f.flush()
    f.write("\n")
    #knn_bits=[]
    #Y_train_bits_enc=[]
    #a='{0:0'+str(alpha)+'b}'
    #for aux in Y_train :
    #    Y_train_bits_enc.append([int(elt) for elt in list(a.format(aux))])
    #for i in range(n):
    #    tmp=[]
    #    for j in range(alpha):
    #        tmp.append(XI[i]*(Y_train_bits_enc[i])[j])
    #    knn_bits.append(tmp)
    #knn=knn_bits[-1]    #convert knn_bits into an encrypted number
    #for i in range(1,alpha):
    #    knn=knn_bits[-1-i]*(2**i)  #ou *HE.encrypt(PyPtxt([2**i], HE)) 
    #result_bits=[]
    return XI


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

#Parameters
p=KEYGEN_PARAMS["p"]
alpha=4 # nb of bits
k=2     # k nearest neighbours
d=3     # d-dimensional vectors
n=100   # n data points
a_class=1 #binary classification (2 classes : 0 and 1)

q=[3,6,2]
f.write("q : "+str(q))
f.write("\n")
#Generate random dataset
f.write("Genrate random X_train and Y_train")
f.write("\n")
X_train=[]
Y_train=[]
for i in range(n):
    tmp=[]
    for j in range(d):
        tmp.append(randint(0,(2**alpha)-1))
    X_train.append(tmp)
    Y_train.append(randint(0,a_class))
f.write("X_train : "+str(X_train))
f.write("\n")
f.write("\n")
f.write("Y_train : "+str(Y_train))
f.write("\n")

f.flush()

f.write("Encrypting q")
f.write("\n")
f.write("\n")
q_enc=[HE.encrypt(PyPtxt([elt], HE) ) for elt in q]
q_bits_enc=[encrypt_as_bits(elt,alpha,HE,f) for elt in q]

f.write("Encrypting X1")
f.write("\n")
x1_enc=[HE.encrypt(PyPtxt([elt], HE) ) for elt in X_train[0]]
x1_bits_enc=[encrypt_as_bits(elt,alpha,HE,f) for elt in X_train[0]]

f.flush()

f.write("\n")
f.write("\n")
f.write("Test l1-norm")
f.write("\n")
f.write("\n")
start = time.time()
result=l1_norm(q_enc,q_bits_enc,x1_enc,x1_bits_enc,HE=HE,alpha=4)
decrypted_res=HE.decrypt(result)
f.flush()
f.write("Distance (q,x1) : "+str(decrypted_res))
f.write("\n")
end=time.time()
f.write(str(end-start)+" sec." )
f.write("\n")

f.flush()

f.write("\n")
f.write("\n")
f.write("Test knn")
f.write("\n")
f.write("\n")
start = time.time()
result=knn(q_enc,q_bits_enc,X_train,Y_train,HE,p,n,d,k,alpha,a_class,file=f)
end=time.time()
f.write(str(end-start)+" sec." )
f.close()
