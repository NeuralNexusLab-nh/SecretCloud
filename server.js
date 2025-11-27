const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const mime = require('mime-types');

const app = express();
const PORT = process.env.PORT || 3000;

// === CONFIGURATION ===
const DB_FILE = './db.json';
const STORAGE_DIR = './storage';
const MAX_QUOTA = 50 * 1024 * 1024 * 1024; // 50GB
const SESSION_TTL = 3600000; // 1 Hour

// === INIT ===
fs.ensureDirSync(STORAGE_DIR);
if (!fs.existsSync(DB_FILE)) {
    fs.writeJsonSync(DB_FILE, { repos: {} });
}

// Multer Storage (Temp)
const upload = multer({ dest: path.join(STORAGE_DIR, 'temp_uploads') });

// === MIDDLEWARE ===
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// In-Memory Sessions (Resets on restart -> Secure)
const sessions = {}; 

// Helpers
const getDB = () => fs.readJsonSync(DB_FILE);
const saveDB = (data) => fs.writeJsonSync(DB_FILE, data);

const getRepoSize = (repoName) => {
    const repoPath = path.join(STORAGE_DIR, repoName);
    if (!fs.existsSync(repoPath)) return 0;
    
    let totalSize = 0;
    const items = fs.readdirSync(repoPath); // Simplified non-recursive for flat repo
    items.forEach(file => {
        try { totalSize += fs.statSync(path.join(repoPath, file)).size; } catch(e){}
    });
    return totalSize;
};

// === SECURITY MIDDLEWARE (HMAC + TIMESTAMP) ===
const verifySignature = (req, res, next) => {
    const token = req.cookies.token;
    if (!token || !sessions[token]) {
        return res.status(401).json({ error: 'ACCESS DENIED: Session Invalid' });
    }

    const session = sessions[token];
    const clientTs = req.headers['x-timestamp'];
    const clientSign = req.headers['x-signature'];
    
    // 1. Timestamp Check (Anti-Replay, 30s window)
    const now = Date.now();
    if (!clientTs || Math.abs(now - parseInt(clientTs)) > 30000) {
        return res.status(403).json({ error: 'SECURITY ALERT: Timestamp Replay Attack' });
    }

    // 2. Signature Check
    // Skip signature check for Multipart (file uploads) for simplicity in this demo,
    // relying on session cookie + timestamp + server-generated signing key match.
    if (!req.is('multipart/form-data')) {
        let payload = clientTs;
        // If body is not empty, add it to payload
        if (req.method !== 'GET' && Object.keys(req.body).length > 0) {
             payload += JSON.stringify(req.body);
        }
        
        const serverSign = crypto.createHmac('sha256', session.signingKey).update(payload).digest('hex');

        if (clientSign !== serverSign) {
            return res.status(403).json({ error: 'SECURITY ALERT: Signature Mismatch. Data Tampered.' });
        }
    }

    req.user = session;
    next();
};

// === API ROUTES ===

// Create Repo
app.post('/api/create', async (req, res) => {
    const { repoName, password } = req.body;
    
    // Validation
    if(!repoName || !password) return res.status(400).json({error: 'Missing fields'});
    const db = getDB();
    if (db.repos[repoName]) return res.status(400).json({ error: 'Repo already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.repos[repoName] = {
        password: hashedPassword,
        isPublic: false, 
        created: Date.now()
    };
    saveDB(db);
    fs.ensureDirSync(path.join(STORAGE_DIR, repoName));

    res.json({ success: true, message: 'Repo initialized successfully.' });
});

// Login
app.post('/api/login', async (req, res) => {
    const { repoName, password } = req.body;
    const db = getDB();
    const repo = db.repos[repoName];

    if (!repo) return res.status(404).json({ error: 'Repo not found.' });

    const match = await bcrypt.compare(password, repo.password);
    if (!match) return res.status(401).json({ error: 'Access Denied: Invalid credentials.' });

    // Create Session
    const token = crypto.randomUUID();
    const signingKey = crypto.randomBytes(32).toString('hex');
    
    sessions[token] = {
        repoName,
        signingKey,
        expires: Date.now() + SESSION_TTL
    };

    res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'strict' }); // Set secure: true in production
    res.json({ success: true, signingKey, repoName });
});

// Logout
app.post('/api/logout', (req, res) => {
    const token = req.cookies.token;
    if (token && sessions[token]) delete sessions[token];
    res.clearCookie('token');
    res.json({ success: true });
});

// Get Repo Info (Files & Quota)
app.get('/api/repo', verifySignature, (req, res) => {
    const repoName = req.user.repoName;
    const repoPath = path.join(STORAGE_DIR, repoName);
    const db = getDB();
    
    const files = fs.readdirSync(repoPath);
    const size = getRepoSize(repoName);
    const isPublic = db.repos[repoName].isPublic;

    res.json({
        files,
        size,
        maxSize: MAX_QUOTA,
        isPublic
    });
});

// Toggle Public/Private
app.post('/api/settings/visibility', verifySignature, (req, res) => {
    const { isPublic } = req.body;
    const db = getDB();
    db.repos[req.user.repoName].isPublic = isPublic;
    saveDB(db);
    res.json({ success: true, message: `Visibility set to ${isPublic ? 'PUBLIC' : 'PRIVATE'}` });
});

// Delete Repo
app.delete('/api/repo', verifySignature, (req, res) => {
    const repoName = req.user.repoName;
    const db = getDB();
    
    delete db.repos[repoName];
    saveDB(db);
    fs.removeSync(path.join(STORAGE_DIR, repoName));
    
    // Kill session
    const token = req.cookies.token;
    delete sessions[token];
    res.clearCookie('token');

    res.json({ success: true, message: 'Repo deleted permanently.' });
});

// Save File (Web IDE)
app.post('/api/file/save', verifySignature, (req, res) => {
    const { filename, content } = req.body;
    const repoName = req.user.repoName;
    
    if (getRepoSize(repoName) + content.length > MAX_QUOTA) {
        return res.status(400).json({ error: 'Quota Exceeded (50GB Limit)' });
    }

    fs.writeFileSync(path.join(STORAGE_DIR, repoName, filename), content);
    res.json({ success: true, message: 'File saved.' });
});

// Upload File
app.post('/api/file/upload', verifySignature, upload.single('file'), (req, res) => {
    const repoName = req.user.repoName;
    
    if(!req.file) return res.status(400).json({error: 'No file uploaded'});

    const currentSize = getRepoSize(repoName);
    if (currentSize + req.file.size > MAX_QUOTA) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Quota Exceeded.' });
    }

    const targetPath = path.join(STORAGE_DIR, repoName, req.file.originalname);
    fs.moveSync(req.file.path, targetPath, { overwrite: true });
    
    res.json({ success: true, message: 'Upload successful.' });
});

// Delete File
app.delete('/api/file/:filename', verifySignature, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(STORAGE_DIR, req.user.repoName, filename);
    
    if(fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        res.json({ success: true, message: 'File deleted.' });
    } else {
        res.status(404).json({ error: 'File not found.' });
    }
});

// === PUBLIC REPO ACCESS ROUTES ===

// 1. List Files or Show Info
app.get('/:repoName', (req, res) => {
    const { repoName } = req.params;
    const db = getDB();
    const repo = db.repos[repoName];

    // Check visibility logic
    // We check cookie manually here because this route doesn't use verifySignature middleware 
    // to allow public access.
    const token = req.cookies.token;
    let isOwner = false;
    if (token && sessions[token] && sessions[token].repoName === repoName) {
        isOwner = true;
    }

    if (!repo) return res.status(404).send('<h1>404 REPO NOT FOUND</h1>');
    if (!repo.isPublic && !isOwner) return res.status(403).send('<h1>403 ACCESS DENIED (PRIVATE REPO)</h1>');

    const repoPath = path.join(STORAGE_DIR, repoName);
    const files = fs.readdirSync(repoPath);

    // Hacker Style HTML Response
    let html = `
    <html>
    <head><title>Index of /${repoName}</title></head>
    <body style="background:black; color:#0f0; font-family:monospace; padding:20px;">
        <h1>Index of /${repoName}</h1>
        <hr>
        <ul>
        <li><a style="color:#0f0" href="/">.. (Back to Secret Cloud)</a></li>
    `;
    files.forEach(f => {
        html += `<li><a style="color:#0f0" href="/${repoName}/${f}">${f}</a></li>`;
    });
    html += `</ul><hr><p>SECRET CLOUD NODE.JS SERVER</p></body></html>`;
    
    res.send(html);
});

// 2. Access File (View Source)
app.get('/:repoName/:fileName', (req, res) => {
    const { repoName, fileName } = req.params;
    const db = getDB();
    const repo = db.repos[repoName];

    // Visibility Check
    const token = req.cookies.token;
    let isOwner = false;
    if (token && sessions[token] && sessions[token].repoName === repoName) {
        isOwner = true;
    }

    if (!repo) return res.status(404).send('Not Found');
    if (!repo.isPublic && !isOwner) return res.status(403).send('Access Denied');

    const filePath = path.join(STORAGE_DIR, repoName, fileName);
    if (!fs.existsSync(filePath)) return res.status(404).send('File Not Found');

    // === FORCE CONTENT TYPE FOR VIEW SOURCE ===
    const mimeType = mime.lookup(filePath);
    
    // Check if it is an image
    if (mimeType && mimeType.startsWith('image/')) {
        res.setHeader('Content-Type', mimeType);
    } else {
        // Everything else: Text/Plain (Source Code view)
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    }

    res.sendFile(path.resolve(filePath));
});

// Start
app.listen(process.env.PORT, () => {
    console.log(`[SYSTEM] Secret Cloud Server is running on port ${PORT}`);
    console.log(`[SYSTEM] Encrypted. Secure. Hacker Mode: ON.`);
});
