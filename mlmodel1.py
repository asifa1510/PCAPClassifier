import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from datetime import datetime
import lightgbm as lgb
import logging

OUTPUT_DIR = r"C:\pcap\datasets\ml"
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(OUTPUT_DIR, 'dataset_processing.log'),
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

CSV_FILES = [
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_DNS.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_LDAP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_MSSQL.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_NetBIOS.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_NTP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_SNMP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_SSDP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\DrDoS_UDP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\Syn.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\TFTP.csv",
    r"C:\pcap\datasets\CSV-01-12\01-12\UDPLag.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Morning.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Monday-WorkingHours.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Tuesday-WorkingHours.pcap_ISCX.csv",
    r"C:\pcap\datasets\MachineLearningCSV\MachineLearningCVE\Wednesday-workingHours.pcap_ISCX.csv",
    r"C:\pcap\datasets\2018-05-09-192.168.100.103_parsed_with_attacks.csv",
    r"C:\pcap\datasets\2018-09-21-capture_parsed_with_attacks.csv"
]

def load_datasets():
    dfs = []
    total_rows = 0
    for file in CSV_FILES:
        if not os.path.exists(file):
            logging.error(f"File not found: {file}")
            print(f"File not found: {file}")
            continue
        try:
            logging.info(f"Starting to process {file}")
            print(f"Starting to process {file}")
            chunks = pd.read_csv(file, chunksize=5000, low_memory=False)
            file_rows = 0
            for i, chunk in enumerate(chunks, 1):
                try:
                    chunk.columns = chunk.columns.str.strip().str.lower().str.replace(' ', '_')
                    logging.info(f"Chunk {i} of {file} columns: {list(chunk.columns)}")
                    required_cols = ['source_ip', 'destination_ip', 'protocol', 'source_port', 
                                     'destination_port', 'packet_length', 'timestamp', 'label']
                    available_cols = [col for col in required_cols if col in chunk.columns]
                    if not available_cols:
                        logging.warning(f"No required columns in chunk {i} of {file}: {list(chunk.columns)}")
                        print(f"No required columns in chunk {i} of {file}")
                        continue
                    chunk = chunk.sample(frac=0.01, random_state=42) 
                    for col in ['source_ip', 'destination_ip', 'protocol', 'label']:
                        if col in chunk.columns:
                            chunk[col] = chunk[col].astype('category')
                    if 'classification' in chunk.columns:
                        chunk = chunk.rename(columns={
                            'source': 'source_ip',
                            'dest': 'destination_ip',
                            'protocol': 'protocol',
                            'source_port': 'source_port',
                            'dest_port': 'destination_port',
                            'length': 'packet_length',
                            'classification': 'label'
                        })
                        chunk['label'] = chunk['label'].apply(
                            lambda x: 'BENIGN' if x == 'BENIGN' else (
                                x.split()[1].strip('()') if isinstance(x, str) and x.startswith('ATTACK') and len(x.split()) > 1 else 'UNKNOWN'
                            )
                        )
                    elif 'label' in chunk.columns:
                        chunk = chunk.rename(columns={
                            'source_ip': 'source_ip',
                            'destination_ip': 'destination_ip',
                            'protocol': 'protocol',
                            'source_port': 'source_port',
                            'destination_port': 'destination_port',
                            'total_length_of_forward_packets': 'packet_length'
                        })
                    if 'timestamp' not in chunk.columns:
                        chunk['timestamp'] = '1970-01-01 00:00:00'
                    cols = ['source_ip', 'destination_ip', 'protocol', 'source_port', 
                            'destination_port', 'packet_length', 'timestamp', 'label']
                    available_cols = [col for col in cols if col in chunk.columns]
                    chunk = chunk[available_cols]
                    dfs.append(chunk)
                    file_rows += len(chunk)
                    logging.info(f"Processed chunk {i} of {file}: {len(chunk)} rows")
                    print(f"Chunk {i} of {file}: {len(chunk)} rows")
                except Exception as e:
                    logging.error(f"Error processing chunk {i} of {file}: {str(e)}")
                    print(f"Error processing chunk {i} of {file}: {str(e)}")
                    continue
            total_rows += file_rows
            logging.info(f"Finished processing {file}: {file_rows} rows")
            print(f"Finished processing {file}: {file_rows} rows")
        except Exception as e:
            logging.error(f"Error reading {file}: {str(e)}")
            print(f"Error reading {file}: {str(e)}")
            continue
    if not dfs:
        raise ValueError("No valid data loaded from CSV files")
    try:
        combined_df = pd.concat(dfs, ignore_index=True)
        combined_df.to_csv(os.path.join(OUTPUT_DIR, 'combined_data.csv'), index=False)
        logging.info(f"Combined {len(combined_df)} rows, saved to '{os.path.join(OUTPUT_DIR, 'combined_data.csv')}'")
        print(f"Combined {len(combined_df)} rows, saved to '{os.path.join(OUTPUT_DIR, 'combined_data.csv')}'")
        return combined_df
    except Exception as e:
        logging.error("Error")
        print(f"Error")
        raise

def preprocess_data(df):
    try:
        df = df.fillna({
            'source_ip': '0.0.0.0',
            'destination_ip': '0.0.0.0',
            'protocol': 'UNKNOWN',
            'source_port': 0,
            'destination_port': 0,
            'packet_length': 0,
            'timestamp': '1970-01-01 00:00:00'
        })
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)
        df['minute'] = df['timestamp'].dt.minute.fillna(0).astype(int)
        df['second'] = df['timestamp'].dt.second.fillna(0).astype(int)
        le_source_ip = LabelEncoder()
        le_dest_ip = LabelEncoder()
        le_protocol = LabelEncoder()
        df['source_ip_encoded'] = le_source_ip.fit_transform(df['source_ip'].astype(str))
        df['destination_ip_encoded'] = le_dest_ip.fit_transform(df['destination_ip'].astype(str))
        df['protocol_encoded'] = le_protocol.fit_transform(df['protocol'].astype(str))
        df['target'] = df['label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
        features = ['source_ip_encoded', 'destination_ip_encoded', 'protocol_encoded',
                    'source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']
        X = df[features]
        y = df['target']
        scaler = StandardScaler()
        X.loc[:, ['source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']] = scaler.fit_transform(
            X[['source_port', 'destination_port', 'packet_length', 'hour', 'minute', 'second']]
        )
        joblib.dump(le_source_ip, os.path.join(OUTPUT_DIR, 'le_source_ip.pkl'))
        joblib.dump(le_dest_ip, os.path.join(OUTPUT_DIR, 'le_dest_ip.pkl'))
        joblib.dump(le_protocol, os.path.join(OUTPUT_DIR, 'le_protocol.pkl'))
        joblib.dump(scaler, os.path.join(OUTPUT_DIR, 'scaler.pkl'))
        logging.info("Preprocessors saved successfully")
        return X, y, df
    except Exception as e:
        logging.error(f"Error in preprocessing: {str(e)}")
        print(f"Error in preprocessing: {str(e)}")
        raise

def train_model(X, y):
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        model = lgb.LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=64,
            class_weight='balanced',
            n_jobs=-1,
            random_state=42
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
        print("Classification Report:\n", classification_report(y_test, y_pred))
        print("Accuracy Score:", accuracy_score(y_test, y_pred))
        joblib.dump(model, os.path.join(OUTPUT_DIR, 'packet_attack_model_lgb.pkl'))
        logging.info(f"Model saved as '{os.path.join(OUTPUT_DIR, 'packet_attack_model_lgb.pkl')}'")
        print(f"Model saved as '{os.path.join(OUTPUT_DIR, 'packet_attack_model_lgb.pkl')}'")
        return model
    except MemoryError:
        logging.error("Memory Error during training")
        print("Memory Error during training")
        return None
    except Exception as e:
        logging.error(f"Error in training: {str(e)}")
        print(f"Error in training: {str(e)}")
        raise

try:
    df = load_datasets()
    X, y, df = preprocess_data(df)
    model = train_model(X, y)
except Exception as e:
    logging.error(f"Fatal Error: {str(e)}")
    print(f"Fatal Error: {str(e)}")
