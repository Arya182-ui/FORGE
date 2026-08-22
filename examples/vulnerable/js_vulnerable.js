const fs = require('fs');
const child_process = require('child_process');

// Hardcoded secrets
const jwtSecret = "super_secret_jwt_token_key_2026";
const apiKey = "AKIAIOSFODNN7EXAMPLE_API_KEY";

function getUser(db, userId) {
    // Vulnerable SQL Injection (String concatenation)
    return db.query("SELECT * FROM users WHERE id = " + userId);
}

function runCommand(userCmd) {
    // Vulnerable Command Injection (exec)
    child_process.exec("ping -c 1 " + userCmd);
}

function runDynamicCode(codeStr) {
    // Vulnerable Eval
    eval(codeStr);
}

function renderContent(element, userInput) {
    // Vulnerable DOM XSS
    element.innerHTML = "<div>" + userInput + "</div>";
}

function getFile(res, userPath) {
    // Vulnerable Path Traversal
    fs.readFile(userPath, 'utf8', (err, data) => {
        res.send(data);
    });
}
