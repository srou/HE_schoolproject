import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pickle


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
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")

#print("  Saving key")
#f = open('key.pckl', 'wb')
#pickle.dump(HE, f)
#f.close()

v1 = [1,2,3,4,5]
v2 = [1,1,1,1,1]

p1 = PyPtxt(v1, HE)
print('plaintext 1 ')
p2 = PyPtxt(v2, HE)


print("Encrypting v1: ", v1)
c1 = HE.encrypt(p1)
print("c1 = ",c1.getIDs(),c1.getLen())
print("Encrypting v2: ", v2)
c2 = HE.encrypt(p2)
print("c2 = ",c2.getIDs(),c2.getLen())


c1 %= c2

r1 = HE.decrypt(c1)

print("Encrypted scalar product v1 .* v2: ", r1)

print "ok"
