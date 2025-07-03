import os
import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, render_template
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, classification_report
import matplotlib
matplotlib.use('Agg')  # Use Agg backend for non-interactive plotting
import matplotlib.pyplot as plt
from flask import send_from_directory
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Load the trained models
svm_model = joblib.load('model/svm_model.pkl')
rf_model = joblib.load('model/random_forest_model.pkl')

# Define the feature columns
features = [' Source Port', ' Destination Port', ' Protocol', ' Flow Duration',
            ' Total Fwd Packets', ' Total Backward Packets',
            'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
            ' Fwd Packet Length Max', ' Fwd Packet Length Min',
            ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
            'Bwd Packet Length Max', ' Bwd Packet Length Min',
            ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
            ' Flow IAT Mean',
            ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total',
            ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
            'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max',
            ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
            ' Fwd URG Flags',
            ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
            'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length',
            ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
            ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count',
            ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count',
            ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count']

# Number of threads to use for SVM predictions
NUM_THREADS = 10  # Adjust this number as needed

def predict_svm_in_chunks(X_scaled):
    chunks = np.array_split(X_scaled, 20)  # Adjust chunk size as needed
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        results = list(executor.map(svm_model.predict, chunks))
    return np.concatenate(results)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the uploaded file
        file = request.files['file']
        # Read the CSV file into a DataFrame
        df = pd.read_csv(file)

        # Extract the feature columns
        X = df[features]

        # Standardize the data
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)

        # Make predictions
        rf_pred = rf_model.predict(X_scaled)
        svm_pred = predict_svm_in_chunks(X_scaled)

        combined_pred = (rf_pred + svm_pred) >= 1
        combined_pred = np.where(combined_pred, 'DDoS', 'BENIGN')

        # Generate pie chart
        labels = ['BENIGN', 'DDoS']
        sizes = [np.sum(combined_pred == 'BENIGN'),
                 np.sum(combined_pred == 'DDoS')]
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%')
        ax.set_title('Prediction Results')
        pie_chart_path = os.path.join('static', 'prediction_pie_chart.png')
        fig.savefig(pie_chart_path)
        plt.close(fig)
        print(f"Saved pie chart to: {pie_chart_path}")

        # Generate bar chart
        label_counts = pd.Series(combined_pred).value_counts()
        fig, ax = plt.subplots()
        ax.bar(label_counts.index, label_counts.values, color=['blue', 'orange'])
        ax.set_xlabel('Prediction')
        ax.set_ylabel('Count')
        ax.set_title('Prediction Counts')
        bar_chart_path = os.path.join('static', 'prediction_bar_chart.png')
        fig.savefig(bar_chart_path)
        plt.close(fig)
        print(f"Saved bar chart to: {bar_chart_path}")


        # Render the results page
        return render_template('results.html',
                               pie_chart='prediction_pie_chart.png',
                               bar_chart='prediction_bar_chart.png')

    return render_template('ddos.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    # Ensure the static directory exists
    if not os.path.exists('static'):
        os.makedirs('static')
    app.run(debug=True)
