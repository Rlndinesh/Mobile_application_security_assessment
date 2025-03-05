import os
import subprocess
import json

def analyze_apk(apk_original_path):
    """Runs Quark analysis on the original APK file instead of the decompiled folder"""
    try:
        results_folder = "backend/quark_results"
        os.makedirs(results_folder, exist_ok=True)

        analysis_output = os.path.join(results_folder, os.path.basename(apk_original_path) + ".json")

        # Ensure Quark runs on the original APK
        quark_command = f'quark -a "{apk_original_path}" -o "{analysis_output}"'
        print(f"Running Quark command: {quark_command}")

        result = subprocess.run(quark_command, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            error_message = result.stderr.strip()
            print("Quark Error Output:", error_message)
            return {"error": f"Analysis failed: {error_message}"}

        if not os.path.exists(analysis_output):
            return {"error": "Analysis failed: Quark did not generate an output file"}

        with open(analysis_output, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception as e:
        return {"error": f"Exception occurred: {str(e)}"}
