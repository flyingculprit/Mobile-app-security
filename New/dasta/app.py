from flask import Flask, request, render_template, redirect, url_for, jsonify
import os
import subprocess
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

def decompile_apk(apk_path, output_dir):
    cmd = f'apktool d -f "{apk_path}" -o "{output_dir}"'
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during decompilation: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file and Config.allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            decompile_result = decompile_apk(file_path, app.config['DECOMPILE_FOLDER'])
            if decompile_result:
                # Placeholder for dynamic analysis
                # This should be replaced with actual dynamic analysis logic
                analysis_result = 'No issues found (placeholder)'

                report_file = os.path.join(app.config['REPORT_FOLDER'], 'report.txt')
                with open(report_file, 'w') as report:
                    report.write(f"Analysis Result:\n{analysis_result}")

                return redirect(url_for('results', filename='report.txt'))
            else:
                return jsonify({'error': 'Decompilation failed'}), 500
    return render_template('index.html')

@app.route('/results/<filename>')
def results(filename):
    return render_template('results.html', filename=filename)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['DECOMPILE_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    app.run(debug=True)
