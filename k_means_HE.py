import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import numpy as np
import pandas as pd 
import time

start = time.time()
HE = Pyfhel()
#Generate Key
KEYGEN_PARAMS={ "p":2,        "r":32,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":30,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
end=time.time()
print("  KeyGen completed in ",start-end," sec." )

#Load Dataset
df=pd.read_csv("./Data_titanic/train.csv", error_bad_lines=False)
print("Number of cols : ",df.shape[1] )
print("Number of rows : ",df.shape[0] )
print("Colnames : ",df.columns.tolist())
#Simplify Dataset (keep only relevant quantitative columns)
df=df[['Survived','Pclass','Age','SibSp','Parch','Fare']]


#Encrypt columns
start = time.time()
p1 = PyPtxt(df['Survived'].tolist(), HE)
print("Encrypting 1st column: ")
c1 = HE.encrypt(p1)
end=time.time()
print(start-end,"sec")

start = time.time()
p2 = PyPtxt(df['Pclass'].tolist(), HE)
print("Encrypting 2nd column: ")
c2 = HE.encrypt(p2)
end=time.time()
print(start-end,"sec")

#sum of the first 2 columns
c1 += c2
r1 = HE.decrypt(c1)
print("Encrypted sum of the first 2 cols : ", r1)
