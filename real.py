from flask import Flask, render_template, request, session
import os
import hashlib
import requests

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.secret_key = 'your_secret_key'  # Add a secret key for session management

# Ensure the upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# MobSF Configuration
MOBSF_BASE_URL = 'http://localhost:8000'
MOBSF_API_KEY = '92fa460c0e52069f5c722c28fe121ac6d34f2d5d7dbb7d8ebb179f159e169b0f'  # Replace with your MobSF API key

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
            return analyze_file(file_hash), file_hash
        else:
            raise Exception("Hash not found in upload response.")
    except Exception as e:
        print(f"Error: {e}")
        return None, None

def perform_reverse_engineering():
    # Retrieve data from session
    file_path = session.get('file_path')
    file_hash = session.get('file_hash')
    print(f"File Path from Session: {file_path}")
    print(f"File Hash from Session: {file_hash}")

    # API URL and headers
    url = f'{MOBSF_BASE_URL}/api/v1/view_source'
    headers = {
        'Authorization': MOBSF_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'  # Correct content type for form data
    }

    # Data to send in the API request
    data = {
        'hash': file_hash,   # MD5 hash of the file
        'type': 'apk',       # Type of file (assume APK here)
        'file': 'uploads/AndroidManifest.xml' # Example of a specific file inside the APK
    }

    # Make the API request
    response = requests.post(url, headers=headers, data=data)

    # Check the response status
    if response.status_code == 200:
        print("Reverse Engineering Successful!")
        return response.json()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return {'error': f"Reverse Engineering Error: {response.text}"}
    

def perform_malware_analysis(apk_path):
    api_key = 'f2cfb80e334d025516a23bfe624ee06ec796e736d10bd2447c94749ec46d6dba'  # Replace with your VirusTotal API key
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': open(apk_path, 'rb')}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('upload.html')

@app.route('/static_analysis', methods=['GET', 'POST'])
def static_analysis():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', result=None, error='No file part')

        file = request.files['file']
        if file.filename == '':
            return render_template('index.html', result=None, error='No selected file')

        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            try:
                result, file_hash = perform_static_analysis(file_path)
                session['file_hash'] = file_hash  # Store the file hash in the session
                session['file_path'] = file_path  # Store the file path in the session
                return render_template('static_analysis.html', result=result, error=None)
            except Exception as e:
                return render_template('static_analysis.html', result=None, error=str(e))

        return render_template('static_analysis.html', result=None, error='File upload failed')
    return render_template('upload.html', title="Static Analysis")

@app.route('/reverse_engineering', methods=['GET', 'POST'])
def reverse_engineering():
    if request.method == 'POST':
        # Handle the uploaded file and perform reverse engineering
        uploaded_file = request.files.get('file')  # Get the uploaded file from the form
        if uploaded_file:
            # Save the uploaded file temporarily
            file_path = os.path.join('uploads', uploaded_file.filename)
            uploaded_file.save(file_path)

            # Generate file hash (you can use SHA256 or MD5)
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()

            # Save to session for further processing
            session['file_path'] = file_path
            session['file_hash'] = file_hash

            # Perform reverse engineering using MobSF API
            try:
                result = perform_reverse_engineering()
                return render_template('reverse_engineering_result.html', result=result)
            except Exception as e:
                return f"Error performing reverse engineering: {str(e)}"
        else:
            return "No file uploaded. Please upload an APK file.", 400
    else:
        # Render the reverse engineering upload form
        return render_template('reverse_engineering.html', title="Reverse Engineering")



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
