var infoPopup;

function togglePopup(id) {
    document.getElementById(id).classList.toggle('show');
}

var capturing = false;
var captureButton = document.getElementById('capturebutton');
function toggleCapture() {
    capturing = !capturing;
    if (capturing) {
        captureButton.style.color = "#4bc551";
        captureButton.style.borderColor = "#4bc551";
    } else {
        captureButton.style.color = "#7e0000";
        captureButton.style.borderColor = "#7e0000";
    }
}

function captureMouseover() {
    captureButton.style.color = "#e4d65a";
    captureButton.style.borderColor = "#e4d65a";
}

function captureMouseleave() {
    if (capturing) {
        captureButton.style.color = "#4bc551";
        captureButton.style.borderColor = "#4bc551";
    } else {
        captureButton.style.color = "#7e0000";
        captureButton.style.borderColor = "#7e0000";
    }
}
// Display a message to the user
var logEl = document.getElementById('log');
function displayLog(msg) {
    var nel = document.createElement('p');
    nel.innerText = msg;
    logEl.appendChild(newElement);
    logEl.appendChild(document.createElement('br'));
}