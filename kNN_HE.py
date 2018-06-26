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
print("  KeyGen completed in "+str(end-start)+" sec." )

#Load Dataset
df1=pd.read_csv("./Data_titanic/train.csv", error_bad_lines=False)
df2=pd.read_csv("./Data_titanic/test.csv", error_bad_lines=False)
print("Number of cols for training set : ",df1.shape[1] )
print("Number of rows for training set : ",df1.shape[0] )
print("Colnames : ",df1.columns.tolist())
#Split data set into input/output and test/train (keep only relevant quantitative columns)
X_train=df1[['Pclass','Age','SibSp','Parch','Fare']]
Y_train=df[['Survived']].tolist()
X_test=df2[['Pclass','Age','SibSp','Parch','Fare']]
Y_test=df2[['Survived']].tolist()


#Encrypt the dataset as a list of rows
start = time.time()
p_Xtrain = PyPtxt(X_train.values.tolist(), HE)
print("Encrypting X_train : ")
c_Xtrain = HE.encrypt(p_Xtrain)
end=time.time()
print(end-start,"sec")

start = time.time()
p_Ytrain = PyPtxt(Y_train.values.tolist(), HE)
print("Encrypting Y_train : ")
c_Ytrain = HE.encrypt(p_Ytrain)
end=time.time()
print(end-start,"sec")

############# voir cb de temps prend cette opération (car à répeter sur tout le test set)
############# et voir si enc([a , b , c])= [enc(a), enc(b), enc(c)] sinon adapter fct
start = time.time()
p_xtest = PyPtxt(X_test.values.tolist()[0], HE)  #x_test 1st row of the test set
print("Encrypting X_test : ")
c_xtest = HE.encrypt(p_Xtest)
end=time.time()
print(end-start,"sec")


#kNN
k=3
import operator
def euclideanDistance(data1, data2, nbcols):
    #Returns the euclidian distance between 2 data points (ie : 2 rows as lists)
    distance = 0
    for x in range(nbcols):
        distance += np.square(data1[x] - data2[x])
    return np.sqrt(distance)

# Defining our KNN model
def knn_HE(X_train, Y_train,x_test, k):
    #Takes in input an encrypted training set and a test point 
    #and returns the inferred class for this test point
    #X_train : input (list of rows)
    #Y_train : output (list of labels)
    distances = {}
    sort = {}
 
    nbcols = X_train.shape[1]
    
    #### Start of STEP 3
    # Calculating euclidean distance between each row of training data and test data
    for x in range(len(X_train)):
        
        #### Start of STEP 3.1
        dist = euclideanDistance(x_test, X_train[x], nbcols)

        distances[x] = dist #distances contient la distance entre chaque instance du train set et le datapoint
        #### End of STEP 3.1
 
    #### Start of STEP 3.2
    # Sorting them on the basis of distance
    sorted_d = sorted(distances.items(), key=operator.itemgetter(1))
    #### End of STEP 3.2
 
    neighbors = []
    
    #### Start of STEP 3.3
    # Extracting top k neighbors (we store their row number)
    for x in range(k):
        neighbors.append(sorted_d[x][0])
    #### End of STEP 3.3
    classVotes = {}
    
    #### Start of STEP 3.4
    # Calculating the most frequent class in the neighbors
    for x in range(len(neighbors)):
        response = Y_train[neighbors[x]]
        if response in classVotes:
            classVotes[response] += 1
        else:
            classVotes[response] = 1
    #### End of STEP 3.4

    #### Start of STEP 3.5
    #return(inferred class,index of k nearest neighbors in the test set)
    sortedVotes = sorted(classVotes.items(), key=operator.itemgetter(1), reverse=True)
    return(sortedVotes[0][0], neighbors)
    #### End of STEP 3.5



#Run the KNN model
print("Run the KNN model on encrypted data : ")
result,neigh = knn_HE(c_Xtrain, c_Ytrain, c_xtest, k)
print(result)