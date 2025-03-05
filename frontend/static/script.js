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
        let tableBody = document.getElementById('resultTableBody');
        tableBody.innerHTML = "";  // Clear existing rows

        if (data.analysis.crimes.length > 0) {
            data.analysis.crimes.forEach(crime => {
                let row = `<tr>
                    <td>${data.apk_filename}</td>
                    <td>${crime.crime}</td>
                    <td>${crime.confidence}</td>
                    <td>${crime.label.join(', ')}</td>
                    <td>${crime.rule}</td>
                    <td>${crime.score}</td>
                    <td>${crime.permissions.length ? crime.permissions.join(', ') : 'None'}</td>
                </tr>`;
                tableBody.innerHTML += row;
            });
        } else {
            tableBody.innerHTML = "<tr><td colspan='7'>No issues found.</td></tr>";
        }
    })
    .catch(error => console.error('Error:', error));
}
