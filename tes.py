import re
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

# ================== PARSER LOG (SUDAH DIPERBAIKI) ==================
def parse_apache_log(log_content, filename):
    logs = []
    lines = log_content.splitlines()
    
    print(f"   📋 Sample 5 baris pertama dari {filename}:")
    for i in range(min(5, len(lines))):
        print(f"      {lines[i][:120]}..." if len(lines[i]) > 120 else f"      {lines[i]}")
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Hapus outer quotes jika ada (penyebab utama error)
        if line.startswith('"') and line.endswith('"'):
            line = line[1:-1].strip()
        
        # Regex utama (Apache Combined Log Format)
        pattern = r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>.*)" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
        match = re.match(pattern, line)
        
        if match:
            request = match.group('request')
            request_parts = request.split()
            if len(request_parts) >= 2:
                method = request_parts[0]
                uri = request_parts[1]
                query = uri.split('?', 1)[1] if '?' in uri else ''
                url_path = uri.split('?')[0]
                
                logs.append({
                    'ip': match.group('ip'),
                    'timestamp': match.group('time'),
                    'method': method,
                    'url': url_path,
                    'query': query,
                    'full_uri': uri,
                    'status': int(match.group('status')),
                    'bytes': int(match.group('bytes')) if match.group('bytes') != '-' else 0,
                    'referer': match.group('referer'),
                    'user_agent': match.group('ua')
                })
    
    print(f"   ✅ Berhasil parse {len(logs):,} baris dari {filename}\n")
    return pd.DataFrame(logs)

# ================== FEATURE EXTRACTION ==================
def extract_features(df):
    df = df.copy()
    df['full_uri_lower'] = df['full_uri'].str.lower()
    
    df['url_length'] = df['full_uri'].str.len()
    df['query_length'] = df['query'].str.len()
    df['special_chars'] = df['full_uri_lower'].str.count(r"['\";<>(){}\[\]/\\%\-]")
    df['param_count'] = df['query'].str.count(r'&') + (df['query'].str.len() > 0).astype(int)
    
    # SQL Injection indicators
    sql_patterns = r'(?i)(select|union|or\s+1=1|sleep|pg_sleep|waitfor|delay|1\'\s*or|cast|convert)'
    df['sql_score'] = df['full_uri_lower'].str.count(sql_patterns)
    
    # XSS indicators
    xss_patterns = r'(?i)(<script|javascript:|onerror|onload|onmouseover|alert\(|eval\(|<img|src=)'
    df['xss_score'] = df['full_uri_lower'].str.count(xss_patterns)
    
    feature_cols = ['url_length', 'query_length', 'special_chars', 
                    'param_count', 'sql_score', 'xss_score', 'status']
    return df, feature_cols

# ================== ELBOW METHOD ==================
def elbow_method(X_scaled, max_k=10):
    inertias = []
    for k in range(1, max_k + 1):
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        kmeans.fit(X_scaled)
        inertias.append(kmeans.inertia_)
    
    plt.figure(figsize=(10, 6))
    plt.plot(range(1, max_k + 1), inertias, marker='o')
    plt.title('Elbow Method - Optimal K')
    plt.xlabel('Jumlah Cluster (K)')
    plt.ylabel('Inertia (WCSS)')
    plt.grid(True)
    plt.show()
    return inertias

# ================== MAIN ==================
def main():
    files = ['acunetix.txt', 'netsparker.txt']
    
    all_logs = []
    for filename in files:
        print(f"🔄 Membaca file lokal: {filename}")
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            df = parse_apache_log(content, filename)
            if not df.empty:
                all_logs.append(df)
        except FileNotFoundError:
            print(f"   ❌ File {filename} tidak ditemukan!")
            return
        except Exception as e:
            print(f"   ❌ Error membaca {filename}: {e}")
            return
    
    if not all_logs:
        print("❌ Tidak ada data yang berhasil diparse. Cek sample baris di atas.")
        return
    
    df_logs = pd.concat(all_logs, ignore_index=True)
    print(f"✅ Total log yang berhasil di-parse: {len(df_logs):,}\n")
    
    # Feature extraction
    df_features, feature_cols = extract_features(df_logs)
    
    X = df_features[feature_cols].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Elbow Method
    print("📊 Menjalankan Elbow Method...")
    elbow_method(X_scaled)
    
    optimal_k = 3  # Ubah setelah melihat plot Elbow
    
    # K-Means
    kmeans = KMeans(n_clusters=optimal_k, random_state=42, n_init=10)
    df_features['cluster'] = kmeans.fit_predict(X_scaled)
    
    # Anomaly scoring
    centroids = kmeans.cluster_centers_
    distances = np.min([np.sum((X_scaled - centroids[i])**2, axis=1) for i in range(optimal_k)], axis=0)
    df_features['anomaly_score'] = distances
    df_features['is_anomaly'] = df_features['anomaly_score'] > np.percentile(df_features['anomaly_score'], 95)
    
    # Simpan hasil
    sqli_df = df_features[df_features['sql_score'] > 0].sort_values(by='anomaly_score', ascending=False)
    xss_df = df_features[df_features['xss_score'] > 0].sort_values(by='anomaly_score', ascending=False)
    
    sqli_df.to_csv('sqli.csv', index=False)
    xss_df.to_csv('xss.csv', index=False)
    df_features.to_csv('web_traffic_anomaly_clusters.csv', index=False)
    
    print("\n✅ BERHASIL MENYIMPAN:")
    print(f"   📁 sqli.csv          : {len(sqli_df):,} record (SQL Injection)")
    print(f"   📁 xss.csv           : {len(xss_df):,} record (XSS Attack)")
    print(f"   📁 web_traffic_anomaly_clusters.csv (semua hasil)")
    
    print("\n📊 RINGKASAN:")
    print(f"   Potensi SQL Injection : {df_features['sql_score'].sum():,}")
    print(f"   Potensi XSS           : {df_features['xss_score'].sum():,}")
    print(f"   Total Anomaly         : {df_features['is_anomaly'].sum():,}")

if __name__ == "__main__":
    main()
