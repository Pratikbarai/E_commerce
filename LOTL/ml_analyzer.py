import pickle
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import re
from datetime import datetime

class MLThreatAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.trained = False

        # LOLBins often abused in LotL and APTs like Volt Typhoon
        self.lolbins = [
            'powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'forfiles.exe', 'debug.exe',
            'certutil.exe', 'bitsadmin.exe', 'netsh.exe', 'schtasks.exe',
            'tasklist.exe', 'sc.exe', 'whoami.exe', 'net.exe', 'nltest.exe'
        ]

        self.suspicious_keywords = [
            'bypass', 'hidden', 'encoded', 'invoke-expression', 'downloadstring',
            'webclient', 'bitstransfer', 'compress-archive', 'invoke-webrequest',
            'scriptblocklogging', 'amsiutils', 'frombase64string'
        ]

        self.network_keywords = ['wget', 'curl', 'net use', 'telnet', 'ftp', 'invoke-webrequest', 'connect']
        self.file_keywords = ['del', 'remove-item', 'copy', 'move', 'xcopy', 'robocopy']
        self.reg_keywords = ['reg add', 'reg delete', 'reg query', 'regedit', 'regsvr32']

    def extract_features(self, process_info):
        features = []

        name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', [])).lower()

        # 1. Process name hash
        features.append(hash(name) % 10000)

        # 2. Command line length
        features.append(len(cmdline))

        # 3. Suspicious keyword count
        features.append(sum(1 for kw in self.suspicious_keywords if kw in cmdline))

        # 4. PowerShell-specific flags
        if 'powershell' in name:
            features.append(1)  # is PowerShell
            features.append(1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', cmdline) else 0)  # base64
            features.append(1 if 'scriptblocklogging' in cmdline else 0)
        else:
            features.extend([0, 0, 0])

        # 5. Network behavior
        features.append(sum(1 for kw in self.network_keywords if kw in cmdline))

        # 6. File behavior
        features.append(sum(1 for kw in self.file_keywords if kw in cmdline))

        # 7. Registry behavior
        features.append(sum(1 for kw in self.reg_keywords if kw in cmdline))

        # 8. Time of day (hour)
        features.append(datetime.now().hour)

        # 9. LOLBin used (process name)
        features.append(1 if name in self.lolbins else 0)

        # 10. LOLBin reference in command-line
        features.append(sum(1 for lb in self.lolbins if lb in cmdline))

        # 11. Known Volt Typhoon tactics
        volt_typhoon_indicators = [
            'netsh interface portproxy', 'sc config', 'schtasks /create',
            'tasklist', 'nltest /domain_trusts', 'dsquery'
        ]
        features.append(sum(1 for kw in volt_typhoon_indicators if kw in cmdline))

        return np.array(features).reshape(1, -1)

    def train_baseline(self, normal_processes):
        if not normal_processes:
            return False

        training_features = [self.extract_features(proc).flatten() for proc in normal_processes]
        X_train = np.array(training_features)
        X_scaled = self.scaler.fit_transform(X_train)

        self.isolation_forest.fit(X_scaled)
        self.trained = True
        return True

    def predict_threat(self, process_info):
        if not self.trained:
            return {'error': 'Model not trained'}

        features = self.extract_features(process_info)
        features_scaled = self.scaler.transform(features)

        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        risk_score = max(0, min(10, (1 - anomaly_score) * 5))

        return {
            'risk_score': risk_score,
            'is_anomaly': is_anomaly,
            'confidence': abs(anomaly_score),
            'features_analyzed': len(features.flatten())
        }

    def save_model(self, filepath):
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'trained': self.trained
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.trained = model_data['trained']
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
