const express = require('express');
const bodyParser = require('body-parser');
const serialize = require('node-serialize');

// --- VULNERABILITY 1: Hardcoded Credentials ---
const DB_PASSWORD = "super_secret_db_password_abc123"; // FAIL: Hardcoded password

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// Mock Database (e.g., MongoDB)
const users = [
    { username: 'admin', password: 'password123', role: 'admin' },
    { username: 'user', password: 'password123', role: 'user' }
];

app.get('/', (req, res) => {
    res.send('<h1>Vulnerable Node.js App</h1>');
});

// --- VULNERABILITY 2: Reflected Cross-Site Scripting (XSS) ---
app.get('/welcome', (req, res) => {
    const name = req.query.name;
    // BAD: User input is inserted directly into the HTML response without escaping.
    // An attacker could provide: <script>alert('XSS');</script>
    res.send(`<h1>Welcome, ${name}!</h1>`); 
});

// --- VULNERABILITY 3: NoSQL Injection (Simulated) ---
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // In a real MongoDB scenario, req.body could contain objects instead of strings.
    // An attacker could send: { "username": "admin", "password": { "$ne": null } }
    // This would bypass the password check because it searches for a password that is "not equal to null".
    const user = users.find(u => u.username === username && u.password === password);

    if (user) {
        res.send(`Logged in as ${user.role}`);
    } else {
        res.send('Login failed');
    }
});

// --- VULNERABILITY 4: Insecure Deserialization ---
// This endpoint accepts a serialized object via a cookie and deserializes it.
// An attacker can craft a malicious serialized object to execute arbitrary code.
// Example payload (base64 encoded):
// {"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('touch /tmp/pwned', function(error, stdout, stderr) { console.log(stdout) });}()"}
app.get('/deserialize', (req, res) => {
    if (req.cookies && req.cookies.profile) {
        try {
            const str = Buffer.from(req.cookies.profile, 'base64').toString();
            
            // BAD: node-serialize's unserialize is known to be insecure.
            const obj = serialize.unserialize(str);
            res.send(`Hello, ${obj.username}`);
        } catch (e) {
            res.send('Error parsing cookie');
        }
    } else {
        res.send('No profile cookie found');
    }
});

// --- VULNERABILITY 5: Regular Expression Denial of Service (ReDoS) ---
app.get('/validate-email', (req, res) => {
    const email = req.query.email;
    // BAD: This regex is vulnerable to catastrophic backtracking.
    // A long string like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" can freeze the server.
    const regex = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/;

    if (regex.test(email)) {
        res.send('Valid Email');
    } else {
        res.send('Invalid Email');
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable server running on port ${PORT}`);
});
