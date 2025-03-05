import os
import subprocess

APKTOOL_PATH = "C:\\apktool\\apktool.bat"

def decompile_apk(apk_path, output_path):
    try:
        # Ensure full absolute paths
        apk_path = os.path.abspath(apk_path)
        output_path = os.path.abspath(output_path)

        # Delete old folder if it exists
        if os.path.exists(output_path):
            subprocess.run(["rmdir", "/s", "/q", output_path], shell=True)

        # Run Apktool with full paths
        cmd = f'"{APKTOOL_PATH}" d -f "{apk_path}" -o "{output_path}"'
        print(f"Running Apktool: {cmd}")
        subprocess.run(cmd, shell=True, check=True)

        print(f"✅ Decompilation successful: {output_path}")
        return output_path

    except subprocess.CalledProcessError as e:
        print(f"❌ Error during decompilation: {e}")
        return None
