import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pickle
import time
from joblib import Parallel, delayed
import multiprocessing
import np

num_cores = multiprocessing.cpu_count()
print ("num of cores : ",num_cores)

HE = Pyfhel()
KEYGEN_PARAMS={ "p":113,      "r":1,
                "d":0,        "c":2,
                "sec":128,    "w":64,
                "L":40,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

#KEYGEN_PARAMS={ "p":123,      "r":1,
#                "d":1,        "c":2,
#                "sec":80,     "w":64,
#                "L":40,       "m":-1,
#                "R":3,        "s":0,
#                "gens":[],    "ords":[]}


print("Pyfhel DEMO")
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
start = time.time()
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

alpha=8
print("Encrypt a list of "+str(alpha)+" ones")
start = time.time()
a=[HE.encrypt(PyPtxt([1], HE)) for i in range(alpha)]
end=time.time()
print("  1st method : "+str(end-start)+" sec." )

start = time.time()
c_1=HE.encrypt(PyPtxt([1], HE))
a=[c_1.copy(c_1) for i in range(alpha)]
end=time.time()
print("  1st method : "+str(end-start)+" sec." )

#print("  Saving key")
#f = open('key.pckl', 'wb')
#pickle.dump(HE, f)
#f.close()



v1 = [1,2,3,4,5]
v2 = [0,1,1,1,1]



print("Encrypting v1: ", v1)
p1 = PyPtxt(v1, HE)
c1 = HE.encrypt(p1)
print("c1 = ",c1.getIDs(),c1.getLen())

print("Encrypting v2: ", v2)
start = time.time()
p2 = PyPtxt(v2, HE)
c2 = HE.encrypt(p2)
print("c2 = ",c2.getIDs(),c2.getLen())
end=time.time()
print('Encryption in '+str(end-start)+' sec')

start = time.time()
c1 %= c2
end=time.time()
print('Scalar product in '+str(end-start)+' sec')

start = time.time()
r1 = HE.decrypt(c1)
end=time.time()
print('Decryption in '+str(end-start)+' sec')

print("Encrypted scalar product v1 .* v2: ", r1)

