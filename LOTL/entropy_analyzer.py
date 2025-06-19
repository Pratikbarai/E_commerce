import math
import os
from collections import Counter
import numpy as np

class EntropyAnalyzer:
    def __init__(self):
        self.encryption_threshold = 7.5
        
    def calculate_file_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if not data:
                return 0.0
                
            # Count byte frequencies
            byte_counts = Counter(data)
            file_size = len(data)
            
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / file_size
                if probability > 0:
                    entropy -= probability * math.log2(probability)
                    
            return entropy
            
        except Exception as e:
            print(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
            
    def analyze_directory_changes(self, directory_path, baseline_entropy=None):
        """Analyze entropy changes in directory (ransomware detection)"""
        current_entropies = {}
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    entropy = self.calculate_file_entropy(file_path)
                    current_entropies[file_path] = entropy
                except:
                    continue
                    
        if baseline_entropy:
            # Compare with baseline
            suspicious_files = []
            for file_path, entropy in current_entropies.items():
                baseline_val = baseline_entropy.get(file_path, 0)
                if entropy > self.encryption_threshold and entropy > baseline_val + 2:
                    suspicious_files.append({
                        'file': file_path,
                        'entropy': entropy,
                        'baseline': baseline_val,
                        'risk': 'HIGH - Possible encryption'
                    })
                    
            return {
                'suspicious_files': suspicious_files,
                'total_files_analyzed': len(current_entropies),
                'high_entropy_count': len(suspicious_files)
            }
        
        return current_entropies
        
    def detect_mass_encryption(self, directory_path, sample_size=50):
        """Quick detection of mass file encryption"""
        high_entropy_count = 0
        total_analyzed = 0
        
        for root, dirs, files in os.walk(directory_path):
            for file in files[:sample_size]:  # Sample first N files
                file_path = os.path.join(root, file)
                entropy = self.calculate_file_entropy(file_path)
                
                if entropy > self.encryption_threshold:
                    high_entropy_count += 1
                    
                total_analyzed += 1
                
                if total_analyzed >= sample_size:
                    break
                    
        encryption_ratio = high_entropy_count / total_analyzed if total_analyzed > 0 else 0
        
        return {
            'encryption_ratio': encryption_ratio,
            'risk_level': 'CRITICAL' if encryption_ratio > 0.7 else 'MEDIUM' if encryption_ratio > 0.3 else 'LOW',
            'high_entropy_files': high_entropy_count,
            'total_analyzed': total_analyzed
        }