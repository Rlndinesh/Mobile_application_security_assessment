from flask import Flask, render_template, request, jsonify
import os
import subprocess
import time

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Ensure the uploads directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Function to extract package name
def get_package_name(apk_path):
    """Extracts the package name from the APK using aapt."""
    try:
        result = subprocess.run(["aapt", "dump", "badging", apk_path], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("package: name="):
                return line.split("'")[1]  # Extract package name
    except Exception as e:
        print(f"Error extracting package name: {e}")
    return None  # Return None if package name not found

# Function to install, launch, and attach Frida to the APK
def perform_dynamic_analysis(apk_path):
    try:
        # Install APK on emulator
        install_result = subprocess.run(["adb", "install", apk_path], capture_output=True, text=True)
        if "Success" not in install_result.stdout:
            return {"error": "Failed to install APK on emulator.", "details": install_result.stderr}

        # Extract package name dynamically
        package_name = get_package_name(apk_path)
        if not package_name:
            return {"error": "Failed to extract package name from APK"}

        # Launch the app on the emulator
        launch_result = subprocess.run(
            ["adb", "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True, text=True
        )
        time.sleep(3)  # Wait for the app to fully start

        # Run Frida to attach to the app
        frida_result = subprocess.run(
            ["frida", "-U", "-n", package_name, "-s", "frida_scripts/hook.js"],
            capture_output=True, text=True
        )

        return {
            "install_output": install_result.stdout,
            "launch_output": launch_result.stdout,
            "frida_output": frida_result.stdout if frida_result.returncode == 0 else frida_result.stderr
        }

    except Exception as e:
        return {"error": f"Dynamic Analysis Failed: {str(e)}"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_apk():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    # Perform dynamic analysis
    result = perform_dynamic_analysis(file_path)
    
    return render_template('result.html', result=result, filename=file.filename)

if __name__ == '__main__':
    app.run(debug=True)
