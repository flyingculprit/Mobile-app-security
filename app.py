import os
import shutil
from flask import Flask, request, render_template
import subprocess
import re

app = Flask(__name__)

# Define the upload and decompile directories
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DECOMPILED_FOLDER'] = 'decompiled'

# Ensure the directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECOMPILED_FOLDER'], exist_ok=True)

def decompile_apk(apk_path, output_dir):
    # Remove the existing directory if it exists
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    cmd = f"apktool d -f '{apk_path}' -o '{output_dir}'"
    print(f"Running command: {cmd}")  # Debug print statement
    subprocess.run(cmd, shell=True, check=True)

def analyze_apk(decompiled_dir):
    issues = []
    
    # Check for hardcoded API keys or secrets
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(".xml") or file.endswith(".smali") or file.endswith(".java"):
                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if "API_KEY" in content or "SECRET_KEY" in content:
                        issues.append(f"Hardcoded key found in {os.path.join(root, file)}")
                    # Check for obfuscated code in .smali files
                    if file.endswith(".smali"):
                        if "goto" in content or "nop" in content or re.search(r'\bL[a-zA-Z0-9]{3,}\b', content):
                            issues.append(f"Potential obfuscated code found in {os.path.join(root, file)}")
                    # Check for suspicious network activity
                    if "http://" in content or "https://" in content or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):
                        issues.append(f"Suspicious network activity found in {os.path.join(root, file)}")

    # Check for dangerous permissions in AndroidManifest.xml
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

    if not issues:
        issues.append("No issues found.")
    
    return issues

@app.route('/', methods=['GET', 'POST'])
def upload_file():
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
                issues = analyze_apk(output_dir)
                return render_template('results.html', issues=issues)
            except subprocess.CalledProcessError as e:
                print(f"Error during decompilation: {e}")
                return f"Error during decompilation: {e}", 500
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
