import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestRegressor
from sklearn.ensemble import RandomForestClassifier
from keras.models import Sequential,Model
from keras.layers import Dense,Input
from keras.optimizers import Adam
import tensorflow as tf
from keras.callbacks import ModelCheckpoint

df = pd.read_csv("rawscan_2.csv",skiprows = [16809], index_col = 0)
df_tier = pd.read_csv("tierInfoDetail.csv",index_col = 0)
df_vpss =  pd.read_csv("data_final_nessus.csv"
                       ,index_col = 0)

#df.drop(df[df['CVSS'] == nan].index, inplace = True)
df = df.dropna(how='any', subset=['Solution'])
df = df[df['Solution']!= "None"]
df = df.reset_index(drop = True)

nessusIP = pd.read_csv("nessusIP.csv")

nessusIP = nessusIP[nessusIP['IP'].notna()]
nessusIP = nessusIP.reset_index(drop = True)

for indx in range(len(df['Host'])):
    x = df['Host'][indx]
    xx = x.replace('.', '')
    if xx.isnumeric() == True:
        df.loc[indx, 'IP'] = x
    else:
        for jndx in range(len(nessusIP['IP'])):
            y = nessusIP['Nessus Host'][jndx]
            y = y.replace('.','')
            if xx == y:
                df.loc[indx, 'IP'] = nessusIP['IP'][jndx]
                break

dfTierDetail = pd.read_csv("tierInfoDetail.csv")

absentHosts = []
count = 0
count2 = 0
flag = 0
for indx in range(len(df['IP'])):
    x = df['IP'][indx]
    xx = x.split('.')
    flag = 0
    for jndx in range(len(dfTierDetail['Hosts'])):
        y1 = dfTierDetail['First IP'][jndx]
        y2 = dfTierDetail['Broadcast'][jndx]
        y1 = y1.split('.')
        y2 = y2.split('.')
        if xx[0:3] == y1[0:3]:
            count = count + 1
            
            if int(y1[3]) < int(xx[3]) < int(y2[3]):
                count2 = count2 + 1
                if dfTierDetail['Security Zone'][jndx] == 'Tier 0':
                    risk = 'Critical'
                elif dfTierDetail['Security Zone'][jndx] == 'Tier 1':
                    risk = 'High'
                elif dfTierDetail['Security Zone'][jndx] == 'Tier 3':
                    risk = 'Medium'
                elif dfTierDetail['Security Zone'][jndx] == 'Tier 4':
                    risk = 'Low'
                df.loc[indx, 'High-Value Asset Identification'] = risk
                flag = 1
                break
    if flag == 0:
        absentHosts.append(x)
           
absentHosts = list(set(absentHosts))

for x in absentHosts:
     df = df[ df['IP'] != x ]

df = df.reset_index(drop =True)

v_counts = df['Host'].value_counts()
df['VPSS'] = df_vpss['Composite Score']
df['Specialist'] = df_vpss['Specialist']
df['Port'] = str(df['Port'])
#df_total_risk = df.groupby('Host')['VPSS'].sum()
#df_total_risk = df_total_risk.sort_values(['VPSS'],ascending = False).reset_index(drop=True)
#df_total_risk.index = np.arange(1, len(df_total_risk) + 1)

## Predicting VPSS
df1 = df.drop(["CVSS", "Host", "Protocol","Description","See Also","Plugin Output","IP","CVE","Specialist"], axis=1)
x_train,x_test,y_train,y_test = train_test_split(df1.loc[:,df1.columns != 'VPSS'],df1['VPSS'],test_size = 0.25)
x_train = x_train.values.tolist()
x_train_corrected = [" ".join(x) for x in x_train]
vectorizer = TfidfVectorizer(lowercase = False,stop_words = 'english')
x_vector = vectorizer.fit_transform(x_train_corrected)
type(x_vector)
print(vectorizer.get_feature_names())

NN_model = Sequential()
# The Input Layer :
NN_model.add(Dense(256, kernel_initializer='he_uniform',input_dim = x_vector.shape[1], activation='relu'))

# The Hidden Layers :
NN_model.add(Dense(128, kernel_initializer='he_uniform',activation='relu'))
NN_model.add(Dense(64, kernel_initializer='he_uniform',activation='relu'))
NN_model.add(Dense(64, kernel_initializer='he_uniform',activation='relu'))


# The Output Layer :
NN_model.add(Dense(1, kernel_initializer='he_uniform',activation='linear'))

# Compile the network :
NN_model.compile(loss='mean_squared_error', optimizer='adam', metrics=['mean_squared_error'])
NN_model.summary()


checkpoint_name = 'Weights-{epoch:03d}--{val_loss:.5f}.hdf5' 
checkpoint = ModelCheckpoint(checkpoint_name, monitor='val_loss', verbose = 1, save_best_only = True, mode ='auto')
callbacks_list = [checkpoint]

NN_model.fit(x_vector, y_train, epochs=200, batch_size=64, validation_split = 0.2, callbacks=callbacks_list)

#print(x_train)
#np.shape(x_vector)
#type(x_vector)
#print(x_vector)

#x_test = x_test.values.tolist()
#x_test_corrected = [" ".join(x) for x in x_test]
#x_vector_test = vectorizer.transform(x_test_corrected)
#
#X_input = Input((x_vector.shape[1],))
#X = Dense(128, input_shape=(x_vector.shape[1],), activation="relu",kernel_initializer='he_uniform')(X_input)
#X = Dense(128, activation="relu",kernel_initializer='he_uniform')(X)
#X = Dense(64, activation="relu",kernel_initializer='he_uniform')(X)
#X = Dense(1, activation="linear",kernel_initializer='he_uniform')(X)
#model = Model(inputs = X_input, outputs = X)
#model.compile(loss="mean_absolute_error", optimizer=Adam(lr=0.001, beta_1=0.9, beta_2=0.999, epsilon=0.01), metrics=["mean_absolute_error"])
#model.fit(x_vector, y_train, batch_size=32, verbose=0)
#
#y_hat_NN = model.predict(x_vector_test)
#y_hat_NN_test = np.argmax(y_hat_NN, axis=1)
##y_hat_NN_test = y_hat_NN_test + 1
#print(accuracy_score(y_test,y_hat_NN_test))
#print(confusion_matrix(y_test,y_hat_NN_test))

#np.shape(x_vector_test)
#num_estimators = []
#accuracy = []
#for i in range(50,500,50):
#    model_rf = RandomForestRegressor(n_estimators=i).fit(x_vector,y_train)
#    y_hat_rf = model_rf.predict(x_vector_test)
#    ac = mean_squared_error(y_test,y_hat_rf)
#    num_estimators.append(i)
#    accuracy.append(ac)

#y_hat_rf = model_rf.predict(x_vector_test)
#
#print(mean_squared_error(y_test,y_hat_rf))


#Predicting Specialist Type
#df2 = df.drop(["CVSS", "Host", "Protocol","Description","See Also","Plugin Output","IP","CVE","VPSS"], axis=1)
#df2['Specialist'] = df2['Specialist'] - 1
#x_train1,x_test1,y_train1,y_test1 = train_test_split(df2.loc[:,df2.columns != 'Specialist'],df2['Specialist'],test_size = 0.25,stratify = df2['Specialist'] )
#x_train1 = x_train1.values.tolist()
#x_train1_corrected = [" ".join(x) for x in x_train1]
#vectorizer1 = TfidfVectorizer(lowercase = False,stop_words = 'english')
#x_vector1 = vectorizer1.fit_transform(x_train1_corrected)
#type(x_vector1)
#print(vectorizer1.get_feature_names())
##print(x_train)
#np.shape(x_vector1)
##type(x_vector1)
##print(x_vector)
#
#x_test1 = x_test1.values.tolist()
#x_test1_corrected = [" ".join(x) for x in x_test1]
#x_vector1_test = vectorizer1.transform(x_test1_corrected)
##np.shape(x_vector_test)
#
#y_train1.value_counts()
#over = BorderlineSMOTE(sampling_strategy={0: 3816, 1: 3000, 2: 2000, 3:1000})
#under = RandomUnderSampler(sampling_strategy={0: 3816, 1: 2500, 2: 1500, 3:500})
#steps = [('o', over), ('u', under)]
#pipeline1 = Pipeline(steps=steps)
#x_vector1, y_train1 = pipeline1.fit_resample(x_vector1, y_train1)


#model_rf_class = RandomForestClassifier(n_estimators=200).fit(x_vector1,y_train1)
#
#y_hat_rf1 = model_rf_class.predict(x_vector1_test)
#
#print(accuracy_score(y_test1,y_hat_rf1))
#print(confusion_matrix(y_test1,y_hat_rf1))

#def convert_sparse_matrix_to_sparse_tensor(X):
#    coo = X.tocoo()
#    indices = np.mat([coo.row, coo.col]).transpose()
#    return tf.SparseTensor(indices, coo.data, coo.shape)
#
#x_tensor = convert_sparse_matrix_to_sparse_tensor(x_vector1)
#x_tensor = tf.cast(x_tensor, tf.float32)
#
#y_tensor=tf.convert_to_tensor(y_train1)

##Changing the output to categorical
#y_train1 = tf.keras.utils.to_categorical(y_train1)
#y_train1 = np.delete(y_train1,0,1)

# Predicting Specialist Type Deep Neural Network

#X_input = Input((x_vector1.shape[1],))
#X = Dense(128, input_shape=(x_vector1.shape[1],), activation="relu",kernel_initializer='he_uniform')(X_input)
#X = Dense(128, activation="relu",kernel_initializer='he_uniform')(X)
#X = Dense(64, activation="relu",kernel_initializer='he_uniform')(X)
#X = Dense(4, activation="softmax",kernel_initializer='he_uniform')(X)
#model = Model(inputs = X_input, outputs = X)
#model.compile(loss="sparse_categorical_crossentropy", optimizer=Adam(lr=0.001, beta_1=0.9, beta_2=0.999, epsilon=0.01), metrics=["accuracy"])
#model.fit(x_vector1, y_train1, batch_size=32, verbose=0)
#
#y_hat_NN = model.predict(x_vector1_test)
#y_hat_NN_test = np.argmax(y_hat_NN, axis=1)
##y_hat_NN_test = y_hat_NN_test + 1
#print(accuracy_score(y_test1,y_hat_NN_test))
#print(confusion_matrix(y_test1,y_hat_NN_test))

