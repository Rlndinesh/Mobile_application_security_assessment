# Mobile Application Security Assessment

This project provides a web-based interface for performing various security assessments on mobile applications, including static analysis, malware analysis, dynamic analysis, and reverse engineering.

## Project Structure

Mobile_application_security_assessment/
│
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── index.html
│   ├── upload.html
│   ├── static_analysis.html
│   ├── malware_analysis.html
│   ├── dynamic_analysis.html
│   ├── reverse_engineering.html
│   └── all_analysis.html
├── static/
│   └── script.js
└── uploads/
## Features

- **Static Analysis**: Uses MoBSF (Mobile Security Framework) for static analysis.
- **Dynamic Analysis**: Uses Frida for dynamic analysis.
- **Malware Analysis**: Uses VirusTotal for malware analysis.
- **Reverse Engineering**: Uses JADX for reverse engineering APK files.


### Prerequisites

- Python 3.x
- Flask
- MoBSF
- Frida
- JADX
- VirusTotal API Key
- MoBSF API Key
## Setup Instructions

1. Clone the repository:
    ```
    git clone https://github.com/Rlndinesh/Mobile_application_security_assessment.git
    cd Mobile_application_security_assessment
    ```

2. Install dependencies:
    ```
    pip install -r requirements.txt
    ```

3. Set up MoBSF:
    - Download and set up Mobile Security Framework (MoBSF) from [MoBSF GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF).
    - Start MoBSF on `http://localhost:8000`.

4. Configure VirusTotal API key:
    - Replace `YOUR_VIRUSTOTAL_API_KEY` in `app.py` with your VirusTotal API key.

5. Configure paths:
    - Update the `aapt` and `jadx` paths in `app.py` to point to the correct locations on your system.

6. Place `script.js` in the `static` directory:
    - This file contains the Frida script for dynamic analysis.

7. Run the Flask application:
    ```
    python app.py
    ```

8. Open your web browser and navigate to `http://127.0.0.1:5000`.

## Usage

1. Navigate to the relevant section (Static Analysis, Malware Analysis, Dynamic Analysis, Reverse Engineering, All Analysis) from the homepage.
2. Upload your APK file and start the analysis.
3. View the results displayed on the webpage.

## Contributions

Contributions are welcome! Please open an issue or create a pull request.


