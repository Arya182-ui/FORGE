const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

// Safe environment variable retrieval
const jwtSecret = process.env.JWT_SECRET;

function getUserSecure(db, userId) {
    // Secure parameterized SQL query
    return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}

function runCommandSecure(hostAddress) {
    // Secure child_process execution passing arguments array with shell: false
    child_process.execFile("ping", ["-c", "1", hostAddress], { shell: false });
}

function renderContentSecure(element, userInput) {
    // Secure DOM text assignment
    element.textContent = userInput;
}

function getFileSecure(res, userFilename) {
    // Secure Path Traversal prevention
    const safePath = path.join(__dirname, 'public', path.basename(userFilename));
    fs.readFile(safePath, 'utf8', (err, data) => {
        res.send(data);
    });
}
