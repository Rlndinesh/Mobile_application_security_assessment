import os
import subprocess
from flask import Flask, request, jsonify, render_template

from utils.decompiler import decompile_apk
from utils.quark_analyzer import analyze_apk

BASE_DIR = os.path.abspath(os.path.dirname(__file__))  

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, "../frontend/templates"),
            static_folder=os.path.join(BASE_DIR, "../frontend/static"))

UPLOAD_FOLDER = 'backend/uploads'
DECOMPILED_FOLDER = 'backend/decompiled'
RESULTS_FOLDER = 'backend/quark_results'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECOMPILED_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

APKTOOL_PATH = "C:\\apktool\\apktool.bat"  # Full path to apktool.bat

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_apk():
    if 'apk' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    apk_file = request.files['apk']
    if apk_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    apk_path = os.path.join(UPLOAD_FOLDER, apk_file.filename)
    apk_file.save(apk_path)

    # Step 1: Decompile APK using full path
    decompiled_path = os.path.join(DECOMPILED_FOLDER, apk_file.filename.replace('.apk', ''))
    try:
        subprocess.run([APKTOOL_PATH, 'd', '-f', apk_path, '-o', decompiled_path], check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Decompilation failed: {str(e)}'}), 500

    # Step 2: Analyze APK
    analysis_result = analyze_apk(apk_path)

    return jsonify({'message': 'File processed successfully', 'analysis': analysis_result})

if __name__ == '__main__':
    app.run(debug=True)
