import pandas as pd
import matplotlib
import numpy as np

pd.set_option('display.max_rows', None)

data = pd.read_csv('bitcoin_transactions_with_timestamps.csv')

data['total_transaction_amount'] = data.groupby(['sender'])['amount'].transform('sum')                                               
data['total_sender_reciever_pair_transaction_amount'] = data.groupby(['sender','receiver'])['amount'].transform('sum')
data['average_transaction_rate'] = data['total_transaction_amount'] / data.groupby(['sender', 'receiver'])['amount'].transform('count')
data['sender_receiver_frequency'] = data.groupby(['sender', 'receiver'])['timestamp'].transform('count')
data['sender_frequency'] = data.groupby(['sender'])['timestamp'].transform('count')

data['malicious'] = (data['amount'] > 100).astype(int)


matplotlib.pyplot.scatter(data['timestamp'],data['amount'])
matplotlib.pyplot.show()

for i in data['sender'].unique():
    print("sender:",i)
    data1=pd.DataFrame()
    data1=pd.concat([data1, data[data['sender'] == i]])
    matplotlib.pyplot.scatter(data1['timestamp'],data1['amount'])
    matplotlib.pyplot.show()
    matplotlib.pyplot.boxplot(data1['amount'])
    fig = matplotlib.pyplot.figure(figsize =(10, 7))
    q1 = np.quantile(data1['amount'], 0.25)
    q3 = np.quantile(data1['amount'], 0.75)
    med = np.median(data1['amount'])
    iqr = q3-q1
    upper_bound = q3+(1.5*iqr)
    lower_bound = q1-(1.5*iqr)
    outliers = data1[(data1['amount'] >= upper_bound)]
    print('The following are the outliers in the boxplot:\n{}'.format(outliers))
    for j in outliers.index:
        data.at[j,'malicious']=1


data.to_csv('modified_data.csv')
