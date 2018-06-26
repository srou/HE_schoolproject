import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pickle
import time


HE = Pyfhel()
KEYGEN_PARAMS={ "p":2,        "r":48,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":32,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("Pyfhel DEMO")
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
start = time.time()
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in "+str(end-start)+" sec." )

#print("  Saving key")
#f = open('key.pckl', 'wb')
#pickle.dump(HE, f)
#f.close()

v1 = [1,2,3,4,5]
v2 = [1,1,1,1,1]



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


c1 %= c2

start = time.time()
r1 = HE.decrypt(c1)
end=time.time()
print('Decryption in '+str(end-start)+' sec')

print("Encrypted scalar product v1 .* v2: ", r1)

print "ok"
