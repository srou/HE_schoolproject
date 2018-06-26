from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
import pickle

print("  Loading key with params : ",{ "p":2,        "r":48,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":32,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]})
f = open('key.pckl', 'rb')
HE = pickle.load(f)
f.close()
print("Key loaded")

v1 = [1,2,3,4,5]
v2 = [2,2,2,2,2]

print("v1: ", v1)
print("v2: ", v2)

ptxt1 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)

ctxt1 = HE.encrypt(ptxt1, fill=1)
ctxt2 = HE.encrypt(ptxt2, fill=1)

print("Encrypted v1: ")
print("len :", ctxt1.getLen()," IDS : ",ctxt1.getIDs())
print("pyfhel attributes : ", dir(ctxt1.getPyfhel()))
print("Encrypted v2: ", ctxt2)

ctxt1 += ctxt2      # `ctxt1 = ctxt1 + ctxt2` would also be valid
v3 = HE.decrypt(ctxt1)
print("add: v1 + v2 -> ", v3)

print("v3: ", v3)
print("v2: ", v2)

ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid
v4 = HE.decrypt(ctxt1)
print("mult: v3 * v2 -> ", v4)
