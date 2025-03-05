function uploadApk() {
    let fileInput = document.getElementById('apkFile');
    let file = fileInput.files[0];

    if (!file) {
        alert("Please select an APK file.");
        return;
    }

    let formData = new FormData();
    formData.append("apk", file);

    fetch('/upload', {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('result').innerText = JSON.stringify(data.analysis, null, 2);
    })
    .catch(error => console.error('Error:', error));
}
