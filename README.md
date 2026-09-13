# Network Anomaly and DDoS Detection System

A machine learning-based network intrusion detection system with an interactive Flask web dashboard. The system analyzes network flow traffic logs in real time, detecting malicious Distributed Denial of Service (DDoS) traffic and identifying benign network activities using an ensemble classification architecture.

---

## System Overview

This application provides automated, real-time threat detection on network traffic captures. By extracting statistical flow characteristics and utilizing a dual-model ensemble (Random Forest and Support Vector Machine), the system achieves high detection recall, minimizing false negatives and protecting network infrastructure against high-volume flood attacks.

---

## Key Features

- **Dual-Model Ensemble Classification:** Combines Random Forest (100 estimators) and Support Vector Machine (RBF kernel) using consensus voting to eliminate single-model blind spots.
- **51-Dimensional Statistical Analysis:** Evaluates packet rates, flow durations, inter-arrival times (IAT), packet length distributions, and TCP control flags (SYN, FIN, RST, PSH, ACK, URG).
- **Interactive Results Dashboard:**
  - **Metric KPI Cards:** Summary counts and percentages for Total Flows, DDoS Anomalies, Benign Flows, and Threat Severity Assessment (Critical, Elevated, Normal).
  - **Dynamic In-Browser Visualizations:** Client-side vector charts (Classification Donut and Model Detection Comparison Bar Chart) powered by Chart.js.
  - **Live Data Records Table:** Inspect real network flows with status badges, instant text/port search, and quick filters (All Flows, DDoS Only, Benign Only).
  - **Forensic CSV Data Exports:** One-click downloads for complete classified records (`predictions_all.csv`), isolated DDoS threats (`predictions_ddos.csv`), or verified benign flows (`predictions_benign.csv`).
- **Parallelized Inference Pipeline:** Employs Python's `ThreadPoolExecutor` to chunk and multithread SVM evaluations across available CPU cores.

---

## Architecture and Workflow

```
+-----------------------------------------------------------------------+
|                    1. Client Upload (CSV File)                        |
+-----------------------------------┬-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                       2. Flask Web Application                        |
|                  - Align 51 network traffic features                  |
|                  - Clean infinite and missing values                  |
+-----------------------------------┬-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                 3. Feature Scaling (scaler.pkl)                       |
|           Normalize all 51 features to [0, 1] range                   |
+-----------------------------------┬-----------------------------------+
                                    |
                 +------------------+------------------+
                 |                                     |
                 v                                     v
+--------------------------------+   +----------------------------------+
|   Random Forest Classifier     |   |          SVM Classifier          |
|      (100 Decision Trees)      |   |       (Multi-Threaded RBF)       |
+----------------┬---------------+   +-----------------┬----------------+
                 |                                     |
                 +------------------+------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                 4. Ensemble Consensus Voting Engine                   |
|                  Rule: (RF Flag + SVM Flag) >= 1                      |
+-----------------------------------┬-----------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                 5. Final Traffic Classification                       |
|                     DDoS Attack  vs.  BENIGN                          |
+-----------------------------------┬-----------------------------------+
                                    |
        +---------------------------+---------------------------+
        |                           |                           |
        v                           v                           v
+-------------------+     +--------------------+     +------------------+
|  KPI Analytics &  |     |   Export CSVs to   |     | Interactive Data |
|   Threat Rating   |     |       Temp/        |     |  Records Table   |
+---------┬---------+     +----------┬---------+     +---------┬--------+
          |                          |                         |
          +--------------------------+-------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------+
|              6. Interactive Web Dashboard (results.html)              |
+-----------------------------------------------------------------------+
```

---

## Repository Structure

```
Anamoly-detection/
├── model/
│   ├── random_forest_model.pkl    # Trained Random Forest classifier
│   ├── svm_model.pkl              # Trained SVM (RBF kernel) classifier
│   └── scaler.pkl                 # Pre-fitted MinMaxScaler for 51 features
├── Temp/                          # Temporary prediction CSV exports (auto-generated)
├── templates/
│   ├── ddos.html                  # File upload interface
│   └── results.html               # Real-time analytics dashboard & data table
├── app.py                         # Flask web application & inference engine
├── model_train.py                 # Offline training, evaluation & model export
├── requirements.txt               # Python package dependencies
├── .gitignore                     # Git ignore rules for environments and cache
├── test.csv                       # 67,000+ row test dataset (ISCX test split)
├── test_sample_balanced.csv       # 2,000 row test dataset (50% DDoS, 50% Benign)
└── test_sample_normal_traffic.csv # 1,000 row test dataset (100% Benign normal traffic)
```

---

## Installation and Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Rithi-20/Anamoly-detection.git
cd Anamoly-detection
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv myenv
.\myenv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv myenv
source myenv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Application

1. Start the Flask application:
   ```bash
   python app.py
   ```
2. Open a web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```
3. Upload any valid network flow CSV file and select **Upload and Predict**.

---

## Included Test Datasets

Pre-formatted test datasets with matching 51-feature headers are included for immediate evaluation:

| File Name | Record Count | Description | Expected Output |
| :--- | :---: | :--- | :--- |
| **`test_sample_balanced.csv`** | 2,000 | 50% Benign traffic, 50% DDoS attack flows | **CRITICAL RISK** (~50% DDoS detected) |
| **`test_sample_normal_traffic.csv`** | 1,000 | 100% Legitimate enterprise network traffic | **NORMAL RISK** (Benign dominant, green) |
| **`test.csv`** | 67,725 | Full holdout split from the ISCX DDoS capture | **CRITICAL RISK** (~59% DDoS detected) |

---

## Machine Learning Methodology

- **Dataset Source:** Canadian Institute for Cybersecurity (CIC-IDS / ISCX DDoS dataset).
- **Feature Normalization:** `MinMaxScaler` fitted exclusively on training distributions to avoid data leakage.
- **Random Forest:** Configured with 100 estimators, parallelized across CPU threads (`n_jobs=16`).
- **Support Vector Machine:** Utilizes the Radial Basis Function (`kernel='rbf'`, `gamma='auto'`) to capture non-linear decision boundaries.
- **Ensemble Strategy:** Consensus OR logic `(rf_pred + svm_pred) >= 1`. If either model detects an anomaly, the flow is classified as a threat to prioritize security recall.

---

## Technology Stack

- **Backend:** Python 3.10+, Flask, Pandas, NumPy, Scikit-learn, Joblib
- **Frontend:** HTML5, CSS3, Bootstrap 5, Bootstrap Icons, Chart.js
- **Concurrency:** ThreadPoolExecutor for chunked multi-threaded inference
