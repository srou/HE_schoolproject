import Pyfhel
from Pyfhel import PyCtxt,PyPtxt,Pyfhel
import pandas as pd 
import time
import math
import numpy as np

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
Y_train=df1[['Survived']].tolist()
X_test=df2[['Pclass','Age','SibSp','Parch','Fare']]
Y_test=df2[['Survived']].tolist()


#Encrypt the dataset as a list of encrypted rows
enc_Xtrain=[]
list_of_rows=X_train.values.tolist()
for i in range(len(list_of_rows)):
    start = time.time()
    p_Xtrain = PyPtxt(list_of_rows[i], HE)
    print("Encrypting "+str(i)+"th row of X_train : ")
    c_Xtrain = HE.encrypt(p_Xtrain)
    end=time.time()
    print(end-start,"sec")
    enc_Xtrain.append(c_Xtrain)

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
c_xtest = HE.encrypt(p_xtest)
end=time.time()
print(end-start,"sec")

#test is_smaller with integers 5 and 6
x_bits=[int(i) for i in list('{0:08b}'.format(5))] #int 5 as a list of bits
x_bits_enc=[]
for i in x_bits :
    p_bit=PyPtxt(x_bits[i],HE)
    c_bit=HE.encrypt(p_bit)
    x_bits_enc.append(c_bit)
y_bits=[int(i) for i in list('{0:08b}'.format(6))] #int 5 as a list of bits
y_bits_enc=[]
for i in y_bits :
    p_bit=PyPtxt(y_bits[i],HE)
    c_bit=HE.encrypt(p_bit)
    y_bits_enc.append(c_bit)
result=is_smaller(x_bits_enc,y_bits_enc)
decrypted_res=HE.decrypt(result)
print("decrypted result : ",decrypted_res)


def is_smaller(x_bits,y_bits,HE=HE,n=10):
    #takes in input 2 encrypted number (st 0=< x,y < n) given in their binary form
    #returns [1] iff y<x , [0] otherwise  (where [1]= encrypt(1))
    #HE is the Homomorphic Encryption scheme (Pyfhel object)

    #Initialisation 
    p_1=PyPtxt(1,HE)
    c_1=HE.encrypt(p_1) #encrypt 1
    same_prefix=[c_1]
    same_bit=[]
    res=(c_1-y_bits[0])*x_bits[0]   ##peut etre faire deepcopy ??
    for i in range(math.floor(math.log(n))+1):
        same_bit.append(c_1-((x_bits[i]-y_bits[i])**2))   ### !!!! voir si la fct **2 marche pour les Ctxt
        tmp=c_1
        for j in range(i+1):
            tmp=tmp*same_bit[j]
        same_prefix.append(tmp)
        res+=(c_1-y_bits[i])*x_bits[i]*same_prefix[i]  ## peut etre un pb d'indice
    return res
    #i=0
    


def l1_norm(a_enc,a_enc_bits,b,b_bits):
    #a_enc : encrypted vector a (list of Ctxt where each Ctxt is an encrypted coefficient of a)
    #a_enc : encrypted bits of each elt of a (list of lists of Ctxt)
    #same for b and b_bits (b doit etre encrypté ???)
    res=0
    for i in range(len(b)):
        iss=is_smaller(b_bits[i],a_enc_bits[i])
        tmp=a_enc[i]-b[i]+2*((b[i]-a_enc[i])*iss)
        res+=tmp
    return res

def convert_to_bit():
    #converts an encrypted number to its bit representation (???)
    #P_bit(x,i)= ith bit of x
    return 0

#def coin_toss()
#def probabilistic_average
#def K_smallest_values()

#kNN over Encrypted Data
def kNN_HE(q_enc,q_bits_enc,X_train,Y_train,HE_scheme,p,n,d,k=3,alpha=1):
    #q_enc =(enc(q1),…,enc(qd)) : list of the encrypted coeffs of q
    #q_bits=([[q1_bits]],…,[[qd_bits]]) : list of lists, where [[q1_bits]] is the list of each encrypted bit of q1
    #X_train : training set (list of rows, each row being a list itself)
    #Y_train : labels associated with X_train
    #n,d : dimensions of X_train (n : nb of rows, d : nb of columns)
    #k : nb of nearest neighbors to output
    #alpha : nb of bits recquired to code the number of classes (??) (ex : if 2 classes, alpha=1)
    #p : prime number such that each value in X_train and q are between 0 and sqrt(p)/d
    #HE_scheme : scheme used for encryption (Pyfhel object)
    
    #Step 1 : calculate distances between q and the rows of X_train
    #initialize distances 
    distances=[]
    for i in range(n):
        b_enc=1  #encrypt X_train[i]
        b_bits_enc=1 #and X_train[i]_bits
        dist=l1_norm(q_enc,q_bits_enc,b_enc,b_bits_enc)
        distances.append(dist)
    return 0


#regular kNN
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
    #Takes in input a training set and a test point 
    #and returns the inferred class for this test point
    #X_train : input (list of rows)
    #Y_train : output (list of labels)
    distances = {}
    sort = {}
 
    nbcols = X_train.shape[1]
    
    # Calculating euclidean distance between each row of training data and test data
    for x in range(len(X_train)):
        
        #### Start of STEP 1
        dist = euclideanDistance(x_test, X_train[x], nbcols)

        distances[x] = dist #distances contient la distance entre chaque instance du train set et le datapoint
        #### End of STEP 1
 
    #### Start of STEP 2
    # Sorting them on the basis of distance
    sorted_d = sorted(distances.items(), key=operator.itemgetter(1))
    #### End of STEP 2
 
    neighbors = []
    
    #### Start of STEP 3
    # Extracting top k neighbors (we store their row number)
    for x in range(k):
        neighbors.append(sorted_d[x][0])
    #### End of STEP 3
    classVotes = {}
    
    #### Start of STEP 4
    # Calculating the most frequent class in the neighbors
    for x in range(len(neighbors)):
        response = Y_train[neighbors[x]]
        if response in classVotes:
            classVotes[response] += 1
        else:
            classVotes[response] = 1
    #### End of STEP 4

    #### Start of STEP 5
    #return(inferred class,index of k nearest neighbors in the test set)
    sortedVotes = sorted(classVotes.items(), key=operator.itemgetter(1), reverse=True)
    return(sortedVotes[0][0], neighbors)
    #### End of STEP 5

#Run the KNN model
#print("Run the KNN model on encrypted data : ")
#result,neigh = knn_HE(c_Xtrain, c_Ytrain, c_xtest, k)
#print(result)