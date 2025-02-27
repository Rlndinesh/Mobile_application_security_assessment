from flask import Flask, render_template, request
import os
import requests
import subprocess

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Function to extract package name using aapt
import requests
import os

# MobSF Configuration
MOBSF_BASE_URL = 'http://localhost:8000'
MOBSF_API_KEY = 'aafb5f5ede326b5e89d895b8bc117719f554dcaa7c6f7392f123b3bfc00a38cd'  # Replace with your MobSF API key

def upload_file_to_mobsf(file_path):
    url = f'{MOBSF_BASE_URL}/api/v1/upload'
    with open(file_path, 'rb') as file:
        files = {'file': ('application.apk', file, 'application/vnd.android.package-archive')}
        headers = {
            'Authorization': MOBSF_API_KEY
        }
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Upload Error: {response.status_code}, {response.text}")


def analyze_file(file_hash):
    url = f'{MOBSF_BASE_URL}/api/v1/scan'
    headers = {
        'Authorization': MOBSF_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'scan_type': 'apk',
        'hash': file_hash
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Analysis Error: {response.status_code}, {response.text}")

def perform_static_analysis(apk_path):
    try:
        upload_response = upload_file_to_mobsf(apk_path)
        if 'hash' in upload_response:
            file_hash = upload_response['hash']
            return analyze_file(file_hash)
        else:
            raise Exception("Hash not found in upload response.")
    except Exception as e:
        print(f"Error: {e}")
        return None

# VirusTotal API integration for malware analysis
def perform_malware_analysis(apk_path):
    api_key = 'f2cfb80e334d025516a23bfe624ee06ec796e736d10bd2447c94749ec46d6dba'  # Replace with your VirusTotal API key
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': open(apk_path, 'rb')}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()

# Frida integration for dynamic analysis
def perform_dynamic_analysis(apk_path):
    package_name = get_package_name(apk_path)
    if not package_name:
        return {'stdout': '', 'stderr': 'Failed to extract package name from APK'}

    script_path = os.path.join(os.getcwd(), 'static', 'script.js')
    
    # Run Frida script here
    process = subprocess.Popen(['frida', '-U', '-f', package_name, '-l', script_path],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return {'stdout': stdout.decode('utf-8'), 'stderr': stderr.decode('utf-8')}

# Reverse Engineering using JADX
def perform_reverse_engineering(apk_path):
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'jadx_output')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    jadx_path = 'D:/mobile_app_security/Mobile_application_security_assessment/jadx/bin/jadx.bat'  # Replace with the actual path to JADX
    subprocess.run([jadx_path, '-d', output_dir, apk_path])
    return output_dir

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static_analysis', methods=['GET', 'POST'])
def static_analysis():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filename)
            # Perform static analysis using MoBSF
            result = perform_static_analysis(filename)
            return render_template('static_analysis.html', filename=uploaded_file.filename, result=result)
    return render_template('upload.html', title="Static Analysis")

@app.route('/malware_analysis', methods=['GET', 'POST'])
def malware_analysis():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filename)
            # Perform malware analysis using VirusTotal
            result = perform_malware_analysis(filename)
            return render_template('malware_analysis.html', filename=uploaded_file.filename, result=result)
    return render_template('upload.html', title="Malware Analysis")

@app.route('/dynamic_analysis', methods=['GET', 'POST'])
def dynamic_analysis():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filename)
            # Perform dynamic analysis using Frida
            result = perform_dynamic_analysis(filename)
            return render_template('dynamic_analysis.html', filename=uploaded_file.filename, result=result)
    return render_template('upload.html', title="Dynamic Analysis")

@app.route('/reverse_engineering', methods=['GET', 'POST'])
def reverse_engineering():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filename)
            # Perform reverse engineering using JADX
            output_dir = perform_reverse_engineering(filename)
            return render_template('reverse_engineering.html', filename=uploaded_file.filename, output_dir=output_dir)
    return render_template('upload.html', title="Reverse Engineering")

@app.route('/all_analysis', methods=['GET', 'POST'])
def all_analysis():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filename)
            # Perform all analyses
            static_result = perform_static_analysis(filename)
            malware_result = perform_malware_analysis(filename)
            dynamic_result = perform_dynamic_analysis(filename)
            reverse_engineering_result = perform_reverse_engineering(filename)
            return render_template('all_analysis.html', filename=uploaded_file.filename, static_result=static_result, malware_result=malware_result, dynamic_result=dynamic_result, reverse_engineering_result=reverse_engineering_result)
    return render_template('upload.html', title="All Analysis")

if __name__ == '__main__':
    app.run(debug=True)


# from flask import Flask, render_template, request
# import os
# import requests
# import subprocess

# app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# if not os.path.exists(app.config['UPLOAD_FOLDER']):
#     os.makedirs(app.config['UPLOAD_FOLDER'])

# def get_package_name(apk_path):
#     try:
#         aapt_path = 'D:/build-tools/30.0.0/aapt.exe'
#         result = subprocess.run([aapt_path, 'dump', 'badging', apk_path], capture_output=True, text=True)
#         for line in result.stdout.splitlines():
#             if line.startswith('package: name='):
#                 package_name = line.split("'")[1]
#                 return package_name
#         return None
#     except Exception as e:
#         return None

# def upload_file_to_mobsf(file_path):
#     url = 'http://localhost:8000/api/v1/upload'
#     files = {'file': open(file_path, 'rb')}
#     headers = {'Authorization': 'YOUR_MOBSF_API_KEY'}
#     response = requests.post(url, files=files, headers=headers)
#     return response.json()

# def scan_file(file_hash):
#     url = f'http://localhost:8000/api/v1/scan/{file_hash}'
#     headers = {'Authorization': 'YOUR_MOBSF_API_KEY'}
#     response = requests.get(url, headers=headers)
#     return response.json()

# def perform_static_analysis(apk_path):
#     upload_response = upload_file_to_mobsf(apk_path)
#     if 'hash' in upload_response:
#         file_hash = upload_response['hash']
#         return scan_file(file_hash)
#     return None

# def perform_malware_analysis(apk_path):
#     api_key = 'YOUR_VIRUSTOTAL_API_KEY'
#     url = 'https://www.virustotal.com/vtapi/v2/file/scan'
#     files = {'file': open(apk_path, 'rb')}
#     params = {'apikey': api_key}
#     response = requests.post(url, files=files, params=params)
#     return response.json()

# def perform_dynamic_analysis(apk_path):
#     package_name = get_package_name(apk_path)
#     if not package_name:
#         return {'stdout': '', 'stderr': 'Failed to extract package name from APK'}

#     script_path = os.path.join(os.getcwd(), 'static', 'script.js')
    
#     process = subprocess.Popen(['frida', '-U', '-f', package_name, '-l', script_path],
#                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     stdout, stderr = process.communicate()
#     return {'stdout': stdout.decode('utf-8'), 'stderr': stderr.decode('utf-8')}

# def perform_reverse_engineering(apk_path):
#     output_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'jadx_output')
#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)
#     jadx_path = 'D:/mobile_app_security/Mobile_application_security_assessment/jadx/bin/jadx.bat'
#     subprocess.run([jadx_path, '-d', output_dir, apk_path])

#     output_files = {}
#     for root, dirs, files in os.walk(output_dir):
#         for file in files:
#             file_path = os.path.join(root, file)
#             with open(file_path, 'r', errors='ignore') as f:
#                 output_files[file] = f.read()
    
#     return output_files

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/static_analysis', methods=['GET', 'POST'])
# def static_analysis():
#     if request.method == 'POST':
#         uploaded_file = request.files['file']
#         if uploaded_file.filename != '':
#             filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
#             uploaded_file.save(filename)
#             result = perform_static_analysis(filename)
#             return render_template('static_analysis.html', filename=uploaded_file.filename, result=result)
#     return render_template('upload.html', title="Static Analysis")

# @app.route('/malware_analysis', methods=['GET', 'POST'])
# def malware_analysis():
#     if request.method == 'POST':
#         uploaded_file = request.files['file']
#         if uploaded_file.filename != '':
#             filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
#             uploaded_file.save(filename)
#             result = perform_malware_analysis(filename)
#             return render_template('malware_analysis.html', filename=uploaded_file.filename, result=result)
#     return render_template('upload.html', title="Malware Analysis")

# @app.route('/dynamic_analysis', methods=['GET', 'POST'])
# def dynamic_analysis():
#     if request.method == 'POST':
#         uploaded_file = request.files['file']
#         if uploaded_file.filename != '':
#             filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
#             uploaded_file.save(filename)
#             result = perform_dynamic_analysis(filename)
#             return render_template('dynamic_analysis.html', filename=uploaded_file.filename, result=result)
#     return render_template('upload.html', title="Dynamic Analysis")

# @app.route('/reverse_engineering', methods=['GET', 'POST'])
# def reverse_engineering():
#     if request.method == 'POST':
#         uploaded_file = request.files['file']
#         if uploaded_file.filename != '':
#             filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
#             uploaded_file.save(filename)
#             output_files = perform_reverse_engineering(filename)
#             return render_template('reverse_engineering.html', filename=uploaded_file.filename, output_files=output_files)
#     return render_template('upload.html', title="Reverse Engineering")

# @app.route('/all_analysis', methods=['GET', 'POST'])
# def all_analysis():
#     if request.method == 'POST':
#         uploaded_file = request.files['file']
#         if uploaded_file.filename != '':
#             filename = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
#             uploaded_file.save(filename)
#             static_result = perform_static_analysis(filename)
#             malware_result = perform_malware_analysis(filename)
#             dynamic_result = perform_dynamic_analysis(filename)
#             reverse_engineering_result = perform_reverse_engineering(filename)
#             return render_template('all_analysis.html', filename=uploaded_file.filename, static_result=static_result, malware_result=malware_result, dynamic_result=dynamic_result, reverse_engineering_result=reverse_engineering_result)
#     return render_template('upload.html', title="All Analysis")

# if __name__ == '__main__':
#     app.run(debug=True)
