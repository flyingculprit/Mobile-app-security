import os
import shutil
from flask import Flask, request, render_template, send_file, send_from_directory, url_for
import subprocess
import re

app = Flask(__name__)

# Define the upload and decompile directories
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DECOMPILED_FOLDER'] = 'decompiled'
app.config['ICON_FOLDER'] = 'static/icons'

# Ensure the directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECOMPILED_FOLDER'], exist_ok=True)
os.makedirs(app.config['ICON_FOLDER'], exist_ok=True)

# Global variables to keep track of the last decompiled directory and icon
global last_decompiled_dir, last_icon_path
last_decompiled_dir = None
last_icon_path = None

def decompile_apk(apk_path, output_dir):
    # Remove the existing directory if it exists
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    cmd = f"apktool d -f '{apk_path}' -o '{output_dir}'"
    print(f"Running command: {cmd}")  # Debug print statement
    subprocess.run(cmd, shell=True, check=True)

def extract_apk_icon(apk_path, icon_path):
    # Use aapt to extract the APK icon
    cmd = f"aapt dump badging '{apk_path}' | grep application-icon"
    output = subprocess.check_output(cmd, shell=True).decode()
    icon_info = re.search(r"\'(.*?)\'", output).group(1)  # Extract icon path
    print(f"Icon info: {icon_info}")  # Debug print statement
    
    if icon_info:
        cmd = f"aapt dump xmltree '{apk_path}' AndroidManifest.xml | grep -A 1 'application' | grep 'icon' | sed 's/.*android:icon=\"//;s/\".*//'"
        icon_name = subprocess.check_output(cmd, shell=True).decode().strip()
        if icon_name:
            icon_cmd = f"aapt dump --values resources '{apk_path}' | grep '{icon_name}' | sed 's/.*android:icon=\"//;s/\".*//'"
            icon_resource = subprocess.check_output(icon_cmd, shell=True).decode().strip()
            subprocess.run(f"aapt dump --values resources '{apk_path}' | grep '{icon_resource}' | sed 's/.*android:icon=\"//;s/\".*//'", shell=True, stdout=open(icon_path, 'wb'))

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
    global last_decompiled_dir, last_icon_path
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
                
                # Extract APK icon
                icon_path = os.path.join(app.config['ICON_FOLDER'], 'icon.png')
                extract_apk_icon(apk_path, icon_path)
                last_icon_path = icon_path
                
                issues = analyze_apk(output_dir)
                return render_template('results.html', issues=issues, icon_url=url_for('static', filename='icons/icon.png'))
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
        for issue in analyze_apk(last_decompiled_dir):
            f.write(issue + '\n')

    return send_file(results_path, as_attachment=True, download_name='analysis_results.txt')

if __name__ == '__main__':
    app.run(debug=True)
