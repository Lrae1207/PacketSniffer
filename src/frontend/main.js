var infoPopup;

function togglePopup(id) {
    document.getElementById(id).classList.toggle('show');
}


// Capture button functionality
var capturing = false;
var captureButton = document.getElementById('capturebutton');
function toggleCapture() {
    capturing = !capturing;
    if (capturing) {
        captureButton.style.color = "#4bc551";
        captureButton.style.borderColor = "#4bc551";
        displayLog("Starting capture...");
    } else {
        captureButton.style.color = "#7e0000";
        captureButton.style.borderColor = "#7e0000";
        displayLog("Stopping capture...");
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

// Feedtable functionality
var feedtable = getElementById('feedtable');
var dataIndex = 1;
// Creates new tr element and create 5 td as the children of the tr.
// The text values of the td elements are assigned a part of the json data.
function addData(json) {
    dataIndex++;
    var tr = document.createElement("tr");
    var num = document.createElement("td");
    num.innerText = dataIndex;
    var src = document.createElement("td");
    src.innerText = json.src;
    var siz = document.createElement("td");
    siz.innerText = json.packetSize;
    var des = document.createElement("td");
    des.innerText = json.des;
    var con = document.createElement("td");
    con.innerText = json.payload;
    var proc = document.createElement("td");
    proc.innerText = json.proc;

    tr.appendChild(num);
    tr.appendChild(src);
    tr.appendChild(des);
    tr.appendChild(siz);
    tr.appendChild(con);
    tr.appendChild(proc);

    feedtable.appendChild(tr);
}

function clearData() {
    if (confirm("Are you sure you want to clear all the data?")) {
        feedtable.innerHTML = "<tr>\n<th>#</th>\n<th>Source</th>\n<th>Dest</th>\n<th>Size(b)</ th>\n<th>Content</th>\n<th>Protocol</th>\n</tr>";
        eel.clear_data();
    }
}

function loadSelectedFile() {

}

// Display a message to the user
var logEl = document.getElementById('log');
function displayLog(msg) {
    var nel = document.createElement('p');
    nel.innerText = msg;
    logEl.appendChild(nel);
}