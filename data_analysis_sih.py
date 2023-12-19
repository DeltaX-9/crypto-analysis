'''
Transaction History:

Number of transactions: Analyze the total number of transactions associated with an account. 
Malicious accounts might have an unusually high number of transactions.
Transaction frequency: Look at how often transactions occur. Malicious accounts might have 
irregular patterns, such as sudden spikes or long periods of inactivity.
Transaction amount: Consider the average transaction amount and whether there are transactions 
with extremely high or low values.

Sender and Receiver Analysis:

Reputation of counterparties: Analyze the reputation of the sender and receiver accounts. Known 
malicious accounts or addresses can be flagged.
Number of counterparties: Evaluate how many different counterparties an account interacts with. Malicious accounts may interact with a wide range of accounts to obfuscate their activities.
Timestamp and Time-based Features:

Transaction timestamp: Consider the time and date of transactions. Detect unusual transaction 
times, such as transactions happening only during certain hours or days.
Time since last transaction: Calculate the time gap between transactions. Malicious accounts may 
exhibit irregular transaction patterns.
Network Graph Features:

Network analysis: Construct a graph of account interactions and analyze network properties such 
as centrality, clustering coefficient, and degree distribution.
Anomaly detection: Apply graph-based anomaly detection algorithms to identify accounts with 
unusual connectivity patterns.
Blockchain-Specific Features:

Smart contract interactions: Analyze whether an account interacts with smart contracts and the 
types of contracts involved.
Gas consumption: Consider the amount of gas consumed by transactions. Unusually high gas 
consumption can be a sign of malicious activities.
Machine Learning Models:

Use supervised learning algorithms (e.g., decision trees, random forests, gradient boosting, 
neural networks) to train a classification model with labeled data (malicious vs. non-malicious 
accounts).
Feature selection: Employ techniques like feature selection to identify the most relevant 
features for classification.
Unsupervised learning: Consider unsupervised learning techniques, such as clustering, to group 
accounts with similar behaviors.
Historical Data:

Use historical blockchain data to create a time series of features, enabling the model to capture 
evolving behavior patterns.
External Data Sources:

Incorporate external data sources, such as known blacklisted addresses or information from threat 
intelligence feeds, to enhance the model's accuracy.
Behavioral Patterns:

Identify behavioral patterns associated with known malicious accounts, such as pump-and-dump 
schemes, Ponzi schemes, or phishing attacks.
Validation and Testing:

Implement robust cross-validation and testing procedures to ensure the model's effectiveness and 
generalizability.
'''

import requests
import json
import mysql.connector as m
import pandas as pd
import numpy as np

score=0

data=requests.get('https://blockchain.info/rawaddr/bc1q7scj57g7m6w6a3hx8h4vvd47nj0yr063f3n3yu')
print(data.json())
d=data.json()
print(type(data.json()))

mo=m.connect(host='localhost',user='root',password='reha',database='sih_analysis_db')
co=mo.cursor()
co.execute('use sih_analysis_db')
co.execute('select sd from common_data')
sd=co.fetchone()
co.execute('select mean from common_data')
mean=co.fetchone()
co.execute('select max_no_transactions from common_data')
max_v=co.fetchone()

#checking total number of transactions
if d['n_tx']>(mean+sd):
    score+=((d['n_tx']-(mean+sd))/max_v)*10

#checking transaction frequency
timevamt=[]
time=[]
amt=[]
for i in d['txs']:
    time.append(i['time'])
    timevamt.append([i['time'],i['result']])
    amt.append(i['result'])
#issue with getting number of transcations per unit time - what unit to take mainly

#checking transaction amounts
amt_series=pd.Series(amt)
q1 = np.quantile(amt_series, 0.25)
q3 = np.quantile(amt_series, 0.75)
iqr = q3-q1
upper_bound = q3+(1.5*iqr)
outliers = amt_series[(amt_series >= upper_bound)]
score+=outliers.size()

#checking reputation of counterparties
