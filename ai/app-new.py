import os
import re
import shutil
import subprocess
from flask import Flask, request, render_template, send_file
from tensorflow.keras.models import load_model
import joblib
import numpy as np
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)

# Define the upload and decompile directories
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DECOMPILED_FOLDER'] = 'decompiled'

# Ensure the directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECOMPILED_FOLDER'], exist_ok=True)

# Load the AI model and scaler
model = load_model('models/security_detection_model.h5')
scaler = joblib.load('models/scaler.pkl')

def decompile_apk(apk_path, output_dir):
    # Remove the existing directory if it exists
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    cmd = f"apktool d -f '{apk_path}' -o '{output_dir}'"
    print(f"Running command: {cmd}")  # Debug print statement
    subprocess.run(cmd, shell=True, check=True)

def run_frida_script(package_name, script_path):
    cmd = f"frida -U -p $(adb shell ps | grep {package_name} | awk '{{print $2}}') -l {script_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def get_package_name(decompiled_dir):
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            match = re.search(r'package="([^"]+)"', content)
            if match:
                return match.group(1)
    return None

def extract_features(decompiled_dir):
    features = {}

    # Count the number of .smali files
    smali_files_count = sum([len(files) for r, d, files in os.walk(decompiled_dir) if any(f.endswith('.smali') for f in files)])
    features['smali_files_count'] = smali_files_count

    # Check for hardcoded API keys or secrets
    hardcoded_keys_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "API_KEY" in content or "SECRET_KEY" in content:
                        hardcoded_keys_count += 1
    features['hardcoded_keys_count'] = hardcoded_keys_count

    # Check for obfuscated code in .smali files
    obfuscated_code_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".smali"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "goto" in content or "nop" in content or re.search(r'\bL[a-zA-Z0-9]{3,}\b', content):
                        obfuscated_code_count += 1
    features['obfuscated_code_count'] = obfuscated_code_count

    # Check for suspicious network activity
    suspicious_network_count = 0
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "http://" in content or "https://" in content or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):
                        suspicious_network_count += 1
    features['suspicious_network_count'] = suspicious_network_count

    # Debug print statements
    print(f"Extracted features: {features}")

    # Ensure the feature order matches the model's training data
    feature_order = ['smali_files_count', 'hardcoded_keys_count', 'obfuscated_code_count', 'suspicious_network_count']
    feature_vector = [features.get(f, 0) for f in feature_order]
    
    return feature_vector

def predict_security_risks(features):
    # Scale the features
    features_scaled = scaler.transform([features])
    # Make prediction
    prediction = model.predict(features_scaled)
    # Interpret the prediction
    threat_level = 'High' if prediction[0] > 0.5 else 'Low'
    return threat_level

def generate_line_plot(features, threat_level):
    # Create a line plot for features
    feature_names = ['smali_files_count', 'hardcoded_keys_count', 'obfuscated_code_count', 'suspicious_network_count']
    feature_values = features

    plt.figure(figsize=(10, 6))
    plt.plot(feature_names, feature_values, marker='o', linestyle='-', color='b')
    plt.title(f'Threat Detection Feature Analysis\nAI Predicted Threat Level: {threat_level}')
    plt.xlabel('Features')
    plt.ylabel('Values')
    plt.grid(True)
    plt.tight_layout()

    # Save the plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    
    # Encode the plot to base64
    img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')
    plt.close()
    
    return img_base64

def analyze_apk(decompiled_dir):
    issues = []
    
    # Extract features from the decompiled APK
    features = extract_features(decompiled_dir)
    
    # Print feature values for debugging
    print(f"Features before scaling and plotting: {features}")

    # Predict security risks using the AI model
    threat_level = predict_security_risks(features)
    issues.append(f"AI Predicted Threat Level: {threat_level}")

    # Generate the line plot
    plot_url = f"data:image/png;base64,{generate_line_plot(features, threat_level)}"

    # Existing code for issue detection
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "API_KEY" in content or "SECRET_KEY" in content:
                        issues.append(f"Hardcoded key found in {os.path.join(root, file)}")
                    if file.endswith(".smali"):
                        if "goto" in content or "nop" in content or re.search(r'\bL[a-zA-Z0-9]{3,}\b', content):
                            issues.append(f"Potential obfuscated code found in {os.path.join(root, file)}")
                    if "http://" in content or "https://" in content or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):
                        issues.append(f"Suspicious network activity found in {os.path.join(root, file)}")

    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            dangerous_permissions = [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.INTERNET"
            ]
            for permission in dangerous_permissions:
                if permission in content:
                    issues.append(f"Dangerous permission {permission} found in AndroidManifest.xml")

    package_name = get_package_name(decompiled_dir)
    if package_name:
        frida_script_path = 'frida_scripts/frida_script.js'
        frida_output = run_frida_script(package_name, frida_script_path)
        if frida_output:
            issues.append(f"Frida analysis results:\n{frida_output}")
    
    if not issues:
        issues.append("No issues found.")
    
    return issues, plot_url

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global last_decompiled_dir
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.apk'):
            filename = file.filename
            apk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(apk_path)
            print(f"File saved to {apk_path}")  # Debug print statement
            try:
                output_dir = os.path.join(app.config['DECOMPILED_FOLDER'], os.path.splitext(filename)[0])
                decompile_apk(apk_path, output_dir)
                last_decompiled_dir = output_dir
                issues, plot_url = analyze_apk(output_dir)
                return render_template('results.html', issues=issues, plot_url=plot_url)
            except subprocess.CalledProcessError as e:
                print(f"Error during decompilation: {e}")
                return f"Error during decompilation: {e}", 500
    return render_template('upload.html')

@app.route('/download_results')
def download_results():
    if last_decompiled_dir is None:
        return "No results available for download.", 400

    # Path to the file where results are stored
    results_path = os.path.join(app.config['DECOMPILED_FOLDER'], 'results.txt')

    # Create and write the results to the file
    with open(results_path, 'w') as f:
        for issue in analyze_apk(last_decompiled_dir)[0]:
            f.write(issue + '\n')

    return send_file(results_path, as_attachment=True, download_name='analysis_results.txt')

if __name__ == '__main__':
    app.run(debug=True)
