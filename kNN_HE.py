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
print("  KeyGen completed in "+str(end-start)" sec." )

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
print(end-start,"sec")

start = time.time()
p2 = PyPtxt(df['Pclass'].tolist(), HE)
print("Encrypting 2nd column: ")
c2 = HE.encrypt(p2)
end=time.time()
print(end-start,"sec")

#test : sum of the first 2 columns
start = time.time()
c1 += c2
r1 = HE.decrypt(c1)
print("Encrypted sum of the first 2 cols : ", r1)
end=time.time()
print(end-start,"sec")

#kNN
k=3
def euclideanDistance(data1, data2, length):
    distance = 0
    for x in range(length):
        distance += np.square(data1[x] - data2[x])
    return np.sqrt(distance)

# Defining our KNN model
def knn(trainingSet, testInstance, k):
 
    distances = {}
    sort = {}
 
    length = testInstance.shape[1]
    
    #### Start of STEP 3
    # Calculating euclidean distance between each row of training data and test data
    for x in range(len(trainingSet)):
        
        #### Start of STEP 3.1
        dist = euclideanDistance(testInstance, trainingSet.iloc[x], length)

        distances[x] = dist[0]
        #### End of STEP 3.1
 
    #### Start of STEP 3.2
    # Sorting them on the basis of distance
    sorted_d = sorted(distances.items(), key=operator.itemgetter(1))
    #### End of STEP 3.2
 
    neighbors = []
    
    #### Start of STEP 3.3
    # Extracting top k neighbors
    for x in range(k):
        neighbors.append(sorted_d[x][0])
    #### End of STEP 3.3
    classVotes = {}
    
    #### Start of STEP 3.4
    # Calculating the most freq class in the neighbors
    for x in range(len(neighbors)):
        response = trainingSet.iloc[neighbors[x]][-1]
 
        if response in classVotes:
            classVotes[response] += 1
        else:
            classVotes[response] = 1
    #### End of STEP 3.4

    #### Start of STEP 3.5
    sortedVotes = sorted(classVotes.items(), key=operator.itemgetter(1), reverse=True)
    return(sortedVotes[0][0], neighbors)
    #### End of STEP 3.5
