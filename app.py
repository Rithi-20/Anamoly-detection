import os
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, render_template, send_from_directory, flash, redirect, url_for
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

app = Flask(__name__)
app.secret_key = 'anomaly_detection_secret_key'

# Load the trained models and pre-fitted scaler
svm_model = joblib.load('model/svm_model.pkl')
rf_model = joblib.load('model/random_forest_model.pkl')
scaler_model = joblib.load('model/scaler.pkl') if os.path.exists('model/scaler.pkl') else None

# Define the 51 feature columns expected by the models
features = [
    ' Source Port', ' Destination Port', ' Protocol', ' Flow Duration',
    ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
    'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max',
    ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length',
    ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std',
    ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count',
    ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count',
    ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count'
]

NUM_THREADS = 10

def predict_svm_in_chunks(X_scaled):
    chunks = np.array_split(X_scaled, 20)
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        results = list(executor.map(svm_model.predict, chunks))
    return np.concatenate(results)

def find_column(df_columns, possible_names):
    for target in possible_names:
        for col in df_columns:
            if col.strip().lower() == target.lower():
                return col
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part provided.', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        try:
            # Read CSV file
            df = pd.read_csv(file)

            # Map features flexibly (supporting both exact and whitespace-trimmed headers)
            clean_col_map = {col.strip(): col for col in df.columns}
            selected_cols = []
            missing_cols = []

            for f in features:
                f_clean = f.strip()
                if f in df.columns:
                    selected_cols.append(f)
                elif f_clean in clean_col_map:
                    selected_cols.append(clean_col_map[f_clean])
                else:
                    missing_cols.append(f_clean)

            if missing_cols:
                # If column names differ but shape matches features
                if len(df.columns) >= len(features):
                    X = df.iloc[:, :len(features)].copy()
                else:
                    flash(f"Uploaded CSV missing {len(missing_cols)} expected feature columns.", 'error')
                    return redirect(request.url)
            else:
                X = df[selected_cols].copy()

            # Clean infinite or NaN values
            X_clean = X.replace([np.inf, -np.inf], np.nan).fillna(0)

            # Standardize using pre-fitted scaler if available
            if scaler_model is not None:
                X_scaled = scaler_model.transform(X_clean)
            else:
                scaler = MinMaxScaler()
                X_scaled = scaler.fit_transform(X_clean)

            # Model Predictions
            rf_pred = rf_model.predict(X_scaled)
            svm_pred = predict_svm_in_chunks(X_scaled)

            # Ensemble classification: Flag DDoS if either model detects an anomaly
            combined_flags = (rf_pred + svm_pred) >= 1
            combined_pred = np.where(combined_flags, 'DDoS', 'BENIGN')

            # Attach prediction results to dataframe
            result_df = df.copy()
            result_df['Ensemble_Prediction'] = combined_pred
            result_df['RF_Prediction'] = np.where(rf_pred == 1, 'DDoS', 'BENIGN')
            result_df['SVM_Prediction'] = np.where(svm_pred == 1, 'DDoS', 'BENIGN')

            # Calculate actual data statistics
            total_records = len(result_df)
            ddos_count = int(np.sum(combined_pred == 'DDoS'))
            benign_count = int(np.sum(combined_pred == 'BENIGN'))
            ddos_pct = round((ddos_count / total_records) * 100, 2) if total_records > 0 else 0
            benign_pct = round((benign_count / total_records) * 100, 2) if total_records > 0 else 0

            rf_ddos_count = int(np.sum(rf_pred == 1))
            svm_ddos_count = int(np.sum(svm_pred == 1))

            if ddos_pct >= 25:
                threat_level = "CRITICAL"
                threat_desc = "High volume of DDoS attack traffic detected."
                threat_badge = "danger"
            elif ddos_pct > 5:
                threat_level = "ELEVATED"
                threat_desc = "Suspicious anomalous traffic detected above normal baseline."
                threat_badge = "warning"
            else:
                threat_level = "NORMAL"
                threat_desc = "Traffic appears benign with minimal or no threat signals."
                threat_badge = "success"

            # Save downloadable prediction CSV files
            os.makedirs('Temp', exist_ok=True)
            all_csv = 'predictions_all.csv'
            ddos_csv = 'predictions_ddos.csv'
            benign_csv = 'predictions_benign.csv'

            result_df.to_csv(os.path.join('Temp', all_csv), index=False)
            result_df[result_df['Ensemble_Prediction'] == 'DDoS'].to_csv(os.path.join('Temp', ddos_csv), index=False)
            result_df[result_df['Ensemble_Prediction'] == 'BENIGN'].to_csv(os.path.join('Temp', benign_csv), index=False)

            # Prepare interactive table preview of real records
            src_port_col = find_column(result_df.columns, ['Source Port', 'src_port', 'sport'])
            dst_port_col = find_column(result_df.columns, ['Destination Port', 'dst_port', 'dport'])
            proto_col = find_column(result_df.columns, ['Protocol', 'proto'])
            dur_col = find_column(result_df.columns, ['Flow Duration', 'duration'])
            fwd_pkts_col = find_column(result_df.columns, ['Total Fwd Packets', 'tot_fwd_pkts'])
            bwd_pkts_col = find_column(result_df.columns, ['Total Backward Packets', 'tot_bwd_pkts'])
            fwd_len_col = find_column(result_df.columns, ['Total Length of Fwd Packets', 'tot_fwd_len'])

            preview_df = result_df.head(150)
            table_rows = []
            for idx, row in preview_df.iterrows():
                proto_val = row[proto_col] if proto_col else 'N/A'
                proto_name = 'TCP (6)' if str(proto_val) == '6' or str(proto_val) == '6.0' else ('UDP (17)' if str(proto_val) == '17' or str(proto_val) == '17.0' else str(proto_val))

                table_rows.append({
                    'id': idx + 1,
                    'src_port': row[src_port_col] if src_port_col else '—',
                    'dst_port': row[dst_port_col] if dst_port_col else '—',
                    'protocol': proto_name,
                    'duration': f"{float(row[dur_col]):,.0f} µs" if dur_col and pd.notna(row[dur_col]) else '—',
                    'fwd_pkts': int(row[fwd_pkts_col]) if fwd_pkts_col and pd.notna(row[fwd_pkts_col]) else '—',
                    'bwd_pkts': int(row[bwd_pkts_col]) if bwd_pkts_col and pd.notna(row[bwd_pkts_col]) else '—',
                    'fwd_len': f"{float(row[fwd_len_col]):,.0f} B" if fwd_len_col and pd.notna(row[fwd_len_col]) else '—',
                    'rf_pred': row['RF_Prediction'],
                    'svm_pred': row['SVM_Prediction'],
                    'prediction': row['Ensemble_Prediction']
                })

            return render_template(
                'results.html',
                filename=file.filename,
                total_records=f"{total_records:,}",
                total_records_raw=total_records,
                ddos_count=f"{ddos_count:,}",
                ddos_count_raw=ddos_count,
                benign_count=f"{benign_count:,}",
                benign_count_raw=benign_count,
                ddos_pct=ddos_pct,
                benign_pct=benign_pct,
                rf_ddos_count=rf_ddos_count,
                svm_ddos_count=svm_ddos_count,
                threat_level=threat_level,
                threat_desc=threat_desc,
                threat_badge=threat_badge,
                table_rows=table_rows,
                preview_count=len(table_rows),
                all_csv=all_csv,
                ddos_csv=ddos_csv,
                benign_csv=benign_csv
            )

        except Exception as e:
            flash(f"Error processing file: {str(e)}", 'error')
            return redirect(request.url)

    return render_template('ddos.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('Temp', filename, as_attachment=True)

if __name__ == '__main__':
    os.makedirs('Temp', exist_ok=True)
    app.run(debug=True)
