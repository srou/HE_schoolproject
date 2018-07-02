from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
HE = Pyfhel()
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":30,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("Pyfhel DEMO")
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")
v1 = [range(8), range(3)]
v2 = [range(1,9), range(1,4)]
v3 = [range(8), range(3)]
v4 = [range(8), range(3)]
v5=[0,1,2]
v6=[1,2,3]

p1 = PyPtxt(v1, HE)
p2 = PyPtxt(v2, HE)
p3 = PyPtxt(v3, HE)
p4 = PyPtxt(v4, HE)
p5 = PyPtxt(v5, HE)
p6 = PyPtxt(v6, HE)


print("Encrypting v1: ", v1)
c1 = HE.encrypt(p1)
print("Encrypting v2: ", v2)
c2 = HE.encrypt(p2)
print("Encrypting v3: ", v3)
c3 = HE.encrypt(p3)
print("Encrypting v4: ", v4)
c4 = HE.encrypt(p4)
print("Encrypting v5: ", v5)
c5 = HE.encrypt(p5)
print("Encrypting v6: ", v6)
c6 = HE.encrypt(p6)

c1 += c4
c2 *= c4
c3 %= c4
c5*=c6

r1 = HE.decrypt(c1)
r2 = HE.decrypt(c2)
r3 = HE.decrypt(c3)

print("Encrypted sum v1 + v4: ", r1)
print("Encrypted mult v2 * v4: ", r2)
print("Encrypted scalar prod v3 * v4: ", r3)
print("multiplication v5*v6 : ",HE.decrypt(c5))

