import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pandastable import Table, TableModel
import re
import os

# ================== CUSTOM STOPWORDS & FUNCTIONS ==================
CUSTOM_STOPWORDS = {
    'http', 'https', 'www', 'com', 'org', 'net', 'html', 'htm', 'asp', 'aspx', 'jsp',
    'index', 'default', 'home', 'main', 'page',
    'images', 'img', 'css', 'js', 'javascript', 'fonts', 'static', 'assets', 'media', 'uploads',
    'http/1.0', 'http/1.1', 'http/2', 'http/2.0',
    'mozilla', '5.0', 'windows', 'nt', 'wow64', 'win64', 'macintosh', 'intel', 'mac', 'os', 'x',
    'linux', 'android', 'iphone', 'ipad', 'applewebkit', 'khtml', 'like', 'gecko', 'trident',
    'chrome', 'firefox', 'safari', 'edge', 'opera', 'msie', 'rv',
    'utf-8', 'gzip', 'deflate', 'keep-alive', 'close', 'connection'
}

def clean_text(text, stopwords_set):
    if not isinstance(text, str) or not text:
        return ""
    tokens = re.findall(r'[a-zA-Z0-9]+', text.lower())
    cleaned = [t for t in tokens if t not in stopwords_set and len(t) > 2]
    return ' '.join(cleaned)

def parse_apache_log(log_content, filename):
    logs = []
    for line in log_content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('"') and line.endswith('"'):
            line = line[1:-1].strip()

        pattern = r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>.*)" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"$'
        match = re.match(pattern, line)
        if match:
            request = match.group('request').split()
            if len(request) >= 2:
                method = request[0]
                uri = request[1]
                query = uri.split('?', 1)[1] if '?' in uri else ''
                url_path = uri.split('?')[0]

                logs.append({
                    'ip': match.group('ip'),
                    'timestamp': match.group('time'),
                    'method': method,
                    'full_uri': uri,
                    'query': query,
                    'status': int(match.group('status')),
                    'bytes': int(match.group('bytes')) if match.group('bytes') != '-' else 0,
                    'referer': match.group('referer'),
                    'user_agent': match.group('ua'),
                    'url_cleaned': clean_text(uri, CUSTOM_STOPWORDS),
                    'source_file': filename
                })
    return pd.DataFrame(logs)

def extract_features(df):
    df = df.copy()
    df['full_uri_lower'] = df['full_uri'].str.lower()
    df['url_length'] = df['full_uri'].str.len()
    df['query_length'] = df['query'].str.len()
    df['special_chars'] = df['full_uri_lower'].str.count(r"['\";<>(){}\[\]/\\%\-]")
    df['param_count'] = df['query'].str.count(r'&') + (df['query'].str.len() > 0).astype(int)
    df['cleaned_url_length'] = df['url_cleaned'].str.len()
    df['cleaned_token_count'] = df['url_cleaned'].str.split().str.len().fillna(0).astype(int)

    sql_patterns = r'(?i)(select|union|or\s+1=1|sleep|pg_sleep|waitfor|delay|1\'\s*or|cast|convert)'
    df['sql_score'] = df['full_uri_lower'].str.count(sql_patterns)

    xss_patterns = r'(?i)(<script|javascript:|onerror|onload|onmouseover|alert\(|eval\(|<img|src=)'
    df['xss_score'] = df['full_uri_lower'].str.count(xss_patterns)
    return df

# ================== TKINTER GUI ==================
class WebAttackDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Attack Detector - Tkinter GUI")
        self.root.geometry("1200x700")

        self.df_features = None
        self.sqli_df = None
        self.xss_df = None
        self.selected_files = []

        self.create_widgets()

    def create_widgets(self):
        # === Top Frame ===
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Button(top_frame, text="📁 Pilih File Log", command=self.select_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="🚀 Proses Data", command=self.process_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="🗑️ Reset", command=self.reset_app).pack(side=tk.LEFT, padx=5)

        self.file_label = ttk.Label(top_frame, text="Belum ada file dipilih")
        self.file_label.pack(side=tk.LEFT, padx=20)

        # === Notebook (Tabs) ===
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab 1: Ringkasan
        self.tab_summary = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_summary, text="Ringkasan")

        # Tab 2: SQL Injection
        self.tab_sqli = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sqli, text="SQL Injection")

        # Tab 3: XSS
        self.tab_xss = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_xss, text="XSS")

        # Tab 4: Semua Data
        self.tab_all = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_all, text="Semua Data + Cluster")

        # Tab 5: Visualisasi
        self.tab_viz = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_viz, text="Visualisasi")

        # Placeholder labels
        ttk.Label(self.tab_summary, text="Klik tombol 'Proses Data' untuk melihat hasil", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_sqli, text="Data SQL Injection akan muncul di sini", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_xss, text="Data XSS akan muncul di sini", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_all, text="Semua data + cluster akan muncul di sini", font=("Arial", 12)).pack(pady=50)

    def select_files(self):
        files = filedialog.askopenfilenames(
            title="Pilih File Log",
            filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")]
        )
        if files:
            self.selected_files = list(files)
            self.file_label.config(text=f"{len(files)} file dipilih")

    def process_data(self):
        if not self.selected_files:
            messagebox.showwarning("Peringatan", "Silakan pilih file log terlebih dahulu!")
            return

        all_logs = []
        for filepath in self.selected_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                df = parse_apache_log(content, os.path.basename(filepath))
                if not df.empty:
                    all_logs.append(df)
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membaca {filepath}\n{str(e)}")
                return

        if not all_logs:
            messagebox.showerror("Error", "Tidak ada data yang berhasil diparse.")
            return

        df_logs = pd.concat(all_logs, ignore_index=True)
        self.df_features = extract_features(df_logs)

        # K-Means
        feature_cols = ['url_length', 'query_length', 'special_chars', 'param_count',
                        'sql_score', 'xss_score', 'status', 'cleaned_url_length', 'cleaned_token_count']
        X = self.df_features[feature_cols].fillna(0)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
        self.df_features['cluster'] = kmeans.fit_predict(X_scaled)

        centroids = kmeans.cluster_centers_
        distances = np.min([np.sum((X_scaled - centroids[i])**2, axis=1) for i in range(3)], axis=0)
        self.df_features['anomaly_score'] = distances
        self.df_features['is_anomaly'] = self.df_features['anomaly_score'] > np.percentile(self.df_features['anomaly_score'], 95)

        self.sqli_df = self.df_features[self.df_features['sql_score'] > 0].sort_values(by='anomaly_score', ascending=False)
        self.xss_df = self.df_features[self.df_features['xss_score'] > 0].sort_values(by='anomaly_score', ascending=False)

        self.update_all_tabs()
        messagebox.showinfo("Sukses", f"Berhasil memproses {len(self.df_features)} baris data!")

    def update_all_tabs(self):
        # Clear old widgets
        for widget in self.tab_summary.winfo_children():
            widget.destroy()
        for widget in self.tab_sqli.winfo_children():
            widget.destroy()
        for widget in self.tab_xss.winfo_children():
            widget.destroy()
        for widget in self.tab_all.winfo_children():
            widget.destroy()
        for widget in self.tab_viz.winfo_children():
            widget.destroy()

        # Ringkasan
        ttk.Label(self.tab_summary, text=f"Total Log: {len(self.df_features)}", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(self.tab_summary, text=f"SQL Injection Terdeteksi: {len(self.sqli_df)}", font=("Arial", 12)).pack()
        ttk.Label(self.tab_summary, text=f"XSS Terdeteksi: {len(self.xss_df)}", font=("Arial", 12)).pack()
        ttk.Label(self.tab_summary, text=f"Anomaly: {self.df_features['is_anomaly'].sum()}", font=("Arial", 12)).pack()

        # SQL Injection Table
        if len(self.sqli_df) > 0:
            self.create_pandastable(self.tab_sqli, self.sqli_df)
        else:
            ttk.Label(self.tab_sqli, text="Tidak ada SQL Injection terdeteksi").pack(pady=50)

        # XSS Table
        if len(self.xss_df) > 0:
            self.create_pandastable(self.tab_xss, self.xss_df)
        else:
            ttk.Label(self.tab_xss, text="Tidak ada XSS terdeteksi").pack(pady=50)

        # All Data
        self.create_pandastable(self.tab_all, self.df_features)

        # Visualisasi
        self.create_visualization_tab()

    def create_pandastable(self, parent, dataframe):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)

        pt = Table(frame, dataframe=dataframe, showtoolbar=True, showstatusbar=True)
        pt.show()

    def create_visualization_tab(self):
        frame = ttk.Frame(self.tab_viz)
        frame.pack(fill=tk.BOTH, expand=True)

        # Elbow Plot
        fig, ax = plt.subplots(figsize=(8, 4))
        inertias = []
        feature_cols = ['url_length', 'query_length', 'special_chars', 'param_count',
                        'sql_score', 'xss_score', 'status', 'cleaned_url_length', 'cleaned_token_count']
        X = self.df_features[feature_cols].fillna(0)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        for k in range(1, 11):
            km = KMeans(n_clusters=k, random_state=42, n_init=10)
            km.fit(X_scaled)
            inertias.append(km.inertia_)

        ax.plot(range(1, 11), inertias, marker='o')
        ax.set_title("Elbow Method")
        ax.set_xlabel("Jumlah Cluster (K)")
        ax.set_ylabel("Inertia")

        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def reset_app(self):
        self.df_features = None
        self.sqli_df = None
        self.xss_df = None
        self.selected_files = []
        self.file_label.config(text="Belum ada file dipilih")

        for widget in self.tab_summary.winfo_children():
            widget.destroy()
        for widget in self.tab_sqli.winfo_children():
            widget.destroy()
        for widget in self.tab_xss.winfo_children():
            widget.destroy()
        for widget in self.tab_all.winfo_children():
            widget.destroy()
        for widget in self.tab_viz.winfo_children():
            widget.destroy()

        ttk.Label(self.tab_summary, text="Klik tombol 'Proses Data' untuk melihat hasil", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_sqli, text="Data SQL Injection akan muncul di sini", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_xss, text="Data XSS akan muncul di sini", font=("Arial", 12)).pack(pady=50)
        ttk.Label(self.tab_all, text="Semua data + cluster akan muncul di sini", font=("Arial", 12)).pack(pady=50)


# ================== RUN APP ==================
if __name__ == "__main__":
    root = tk.Tk()
    app = WebAttackDetectorApp(root)
    root.mainloop()
