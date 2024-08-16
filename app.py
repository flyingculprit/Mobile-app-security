import os
import shutil
from flask import Flask, request, render_template, send_file, redirect, url_for
import subprocess
import re
from zipfile import ZipFile
from io import BytesIO
from PIL import Image

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DECOMPILED_FOLDER'] = 'decompiled'
app.config['ICON_FOLDER'] = 'static/icons'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECOMPILED_FOLDER'], exist_ok=True)
os.makedirs(app.config['ICON_FOLDER'], exist_ok=True)

global last_decompiled_dir, apk_icon_path
last_decompiled_dir = None
apk_icon_path = None

def decompile_apk(apk_path, output_dir):
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    cmd = f"apktool d -f '{apk_path}' -o '{output_dir}'"
    subprocess.run(cmd, shell=True, check=True)

def extract_icon(apk_path):
    with ZipFile(apk_path, 'r') as apk:
        icon_files = [f for f in apk.namelist() if f.endswith('.png') and 'mipmap' in f or 'drawable' in f]
        if icon_files:
            largest_icon = max(icon_files, key=lambda x: apk.getinfo(x).file_size)
            with apk.open(largest_icon) as icon_file:
                icon_path = os.path.join(app.config['ICON_FOLDER'], os.path.basename(largest_icon))
                with open(icon_path, 'wb') as f:
                    shutil.copyfileobj(icon_file, f)
            return icon_path
    return None

def analyze_apk(decompiled_dir):
    issues = []
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

    if not issues:
        issues.append("No issues found.")
    
    return issues

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global last_decompiled_dir, apk_icon_path
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.apk'):
            filename = file.filename
            apk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(apk_path)
            try:
                output_dir = os.path.join(app.config['DECOMPILED_FOLDER'], os.path.splitext(filename)[0])
                decompile_apk(apk_path, output_dir)
                last_decompiled_dir = output_dir

                apk_icon_path = extract_icon(apk_path)

                issues = analyze_apk(output_dir)
                return render_template('results.html', issues=issues, icon=apk_icon_path, apk_name=filename)
            except subprocess.CalledProcessError as e:
                return f"Error during decompilation: {e}", 500
    return render_template('upload.html')

@app.route('/download_results')
def download_results():
    if last_decompiled_dir is None:
        return "No results available for download.", 400

    results_path = os.path.join(app.config['DECOMPILED_FOLDER'], 'results.txt')

    with open(results_path, 'w') as f:
        for issue in analyze_apk(last_decompiled_dir):
            f.write(issue + '\n')

    return send_file(results_path, as_attachment=True, download_name='analysis_results.txt')

if __name__ == '__main__':
    app.run(debug=True)
