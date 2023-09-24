import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
pd.set_option('display.max_rows', None)


# Load your dataset with timestamps
data = pd.read_csv('bitcoin_transactions_with_timestamps.csv')

# Feature engineering: Calculate total transaction amount, average transaction rate, and sender-receiver frequency
data['total_transaction_amount'] = data.groupby(['sender', 'receiver'])['amount'].transform('sum')
data['average_transaction_rate'] = data['total_transaction_amount'] / data.groupby(['sender', 'receiver'])['amount'].transform('count')
data['sender_receiver_frequency'] = data.groupby(['sender', 'receiver'])['timestamp'].transform('count')

# Labeling: Create a column 'malicious' based on the criteria (e.g., >100 Bitcoin)
data['malicious'] = (data['total_transaction_amount'] > 100).astype(int)

# Split data into training and testing sets
X = data[['total_transaction_amount', 'average_transaction_rate', 'sender_receiver_frequency']]
y = data['malicious']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create and train a Random Forest classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Make predictions on the test set
y_pred = clf.predict(X_test)

# Display which transactions are malicious (1) and which are not (0)
test_data = X_test.copy()
test_data['prediction'] = y_pred

# Create separate DataFrames for sender and receiver IDs
senders = data['sender'].unique()
receivers = data['receiver'].unique()

# Display sender and receiver IDs
sender_df = pd.DataFrame({'sender_id': senders})
receiver_df = pd.DataFrame({'receiver_id': receivers})

print("Predictions (1: Malicious, 0: Not Malicious):")
print(test_data)

print("\nSender IDs:")
print(sender_df)

print("\nReceiver IDs:")
print(receiver_df)
