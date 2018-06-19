import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import numpy as np
#Instantiate a Pyfhel object called HE.
HE = Pyfhel()

print("******Generation of the keys for encryption******")

#Create the Key Generator parameters.
KEYGEN_PARAMS={ "p":257,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

"""Print the Key Generator parameters to let the user knows how his vectors will be encrypted."""
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)

"""Generate the keys that will be use to encrypted the vectors. The generation of the keys uses the Key Generator parameters. Then print a message to inform the user that the key generation has been completed."""
HE.keyGen(KEYGEN_PARAMS)

#input vector (ie : le vecteur v sur lequel on applique le )
v_poly= [1,2,3,4,5]
#turn this vector into a plaintext
ptxt_poly = PyPtxt(v_poly, HE)
#encrypt in a cyphertext
ctxt_poly = HE.encrypt(ptxt_poly)
print("------------------TEST Polynomial function----------------------")

#coeffs of the polynomial
a0 = [1,1,1,1,1]
a1 = [1,1,1,1,1]
a2 = [1,1,1,1,1]
a3 = [1,1,1,1,1]

pltxt0 = PyPtxt(a0, HE)
pltxt1 = PyPtxt(a1, HE)
pltxt2 = PyPtxt(a2, HE)
pltxt3 = PyPtxt(a3, HE)

cytxt0 = HE.encrypt(pltxt0)
cytxt1 = HE.encrypt(pltxt1)
cytxt2 = HE.encrypt(pltxt2)
cytxt3 = HE.encrypt(pltxt3)

print("Polynome: a0 + a1 * v + a2 * v**2 + a3 * v**3")
print("Decrypt(coefficient_a0): ", HE.decrypt(cytxt0))
print("Decrypt(coefficient_a1): ", HE.decrypt(cytxt1))
print("Decrypt(coefficient_a2): ", HE.decrypt(cytxt2))
print("Decrypt(coefficient_a3): ", HE.decrypt(cytxt3))
print("Decrypt(v): ", HE.decrypt(ctxt_poly))

coeff = [cytxt0, cytxt1, cytxt2, cytxt3]

ctxt_polynomial = ctxt_poly.polynomialMult(coeff)
result = HE.decrypt(ctxt_polynomial)
print("Polynomial result: ", result)

ppar = [1, 1, 1, 1]
p = np.poly1d(ppar)
print("Polynomial evaluation on unencrypted vector:")
print(p(1), ", ", p(2), ", ", p(3), ", ", p(4), ", ", p(5))