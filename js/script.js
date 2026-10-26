const startScanBtn = document.getElementById("startScanBtn");

startScanBtn.addEventListener("click", function () {

    alert(
        "Security Scan Module will open here.\n\n" +
        "Frontend is working successfully!"
    );

});
function startScan() {

    const url = document.getElementById("websiteURL").value;

    if (url === "") {

        alert("Please enter a website URL.");

        return;
    }

    localStorage.setItem("targetURL", url);

    window.location.href = "scanning.html";
}
const targetURL = document.getElementById("targetURL");

if (targetURL) {

    const savedURL = localStorage.getItem("targetURL");

    if (savedURL) {
        targetURL.textContent = savedURL;
    }
}
const reportURL = document.getElementById("reportURL");

if (reportURL) {

    const savedURL = localStorage.getItem("targetURL");

    if (savedURL) {
        reportURL.textContent = savedURL;
    }

}