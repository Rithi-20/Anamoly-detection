# Import necessary packages
import joblib
from sklearn.metrics import precision_score, recall_score, f1_score
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
df = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

# Feature columns
features = [' Source Port', ' Destination Port', ' Protocol', ' Flow Duration',
            ' Total Fwd Packets', ' Total Backward Packets',
            'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
            ' Fwd Packet Length Max', ' Fwd Packet Length Min',
            ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
            'Bwd Packet Length Max', ' Bwd Packet Length Min',
            ' Bwd Packet Length Mean', ' Bwd Packet Length Std', ' Flow IAT Mean',
            ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total',
            ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
            'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max',
            ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags',
            ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
            'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length',
            ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
            ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count',
            ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count',
            ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count']

# Separate features (X) and labels (y)
X = df[features]
df[' Label'] = df[' Label'].map({'BENIGN': 0, 'DDoS': 1})
y = df[' Label']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
X_test.to_csv('test.csv',index = False)

# Standardize the data
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 1. Random Forest for supervised classification
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=16)
rf_model.fit(X_train_scaled, y_train)
rf_pred = rf_model.predict(X_test_scaled)
print(rf_pred)

# 2. SVM classifier
svm_model = SVC(kernel='rbf', random_state=42, gamma='auto')
svm_model.fit(X_train_scaled, y_train)
svm_pred = svm_model.predict(X_test_scaled)


# Voting mechanism: majority voting for classification
combined_pred = (rf_pred + svm_pred) >= 1  # If either model predicts DDoS (1), classify as DDoS (1)
print(combined_pred)
# Evaluate Random Forest performance
rf_accuracy = accuracy_score(y_test, rf_pred)
rf_precision = precision_score(y_test, rf_pred)
rf_recall = recall_score(y_test, rf_pred)
rf_f1 = f1_score(y_test, rf_pred)


print("Random Forest Accuracy:", rf_accuracy)
print("Random Forest Precision:", rf_precision)
print("Random Forest Recall:", rf_recall)
print("Random Forest F1 Score:", rf_f1)

# Evaluate SVM performance
svm_accuracy = accuracy_score(y_test, svm_pred)
svm_precision = precision_score(y_test, svm_pred)
svm_recall = recall_score(y_test, svm_pred)
svm_f1 = f1_score(y_test, svm_pred)

print("SVM Accuracy:", svm_accuracy)
print("SVM Precision:", svm_precision)
print("SVM Recall:", svm_recall)
print("SVM F1 Score:", svm_f1)

# Evaluate combined model performance
combined_accuracy = accuracy_score(y_test, combined_pred)
combined_precision = precision_score(y_test, combined_pred)
combined_recall = recall_score(y_test, combined_pred)
combined_f1 = f1_score(y_test, combined_pred)

print("Combined Model Accuracy:", combined_accuracy)
print("Combined Model Precision:", combined_precision)
print("Combined Model Recall:", combined_recall)
print("Combined Model F1 Score:", combined_f1)

# Save the Random Forest model
joblib.dump(rf_model, 'model/random_forest_model.pkl')

# Save the SVM model
joblib.dump(svm_model, 'model/svm_model.pkl')

joblib.dump(scaler, 'model/scaler.pkl')
