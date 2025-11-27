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

// === 設定 ===
const DB_FILE = './db.json';
const STORAGE_DIR = './storage';
const MAX_QUOTA = 50 * 1024 * 1024 * 1024; // 50GB
const SESSION_TTL = 3600000; // 1小時

// === 初始化 ===
fs.ensureDirSync(STORAGE_DIR);
if (!fs.existsSync(DB_FILE)) {
    fs.writeJsonSync(DB_FILE, { repos: {} });
}

// Multer 設定
const upload = multer({ dest: path.join(STORAGE_DIR, 'temp_uploads') });

// === Middleware ===
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public')); // 提供靜態檔案 (CSS, JS)

// Session Store (記憶體)
const sessions = {}; 

// DB Helper
const getDB = () => fs.readJsonSync(DB_FILE);
const saveDB = (data) => fs.writeJsonSync(DB_FILE, data);

// 計算大小
const getRepoSize = (repoName) => {
    const repoPath = path.join(STORAGE_DIR, repoName);
    if (!fs.existsSync(repoPath)) return 0;
    let totalSize = 0;
    fs.readdirSync(repoPath).forEach(file => {
        try { totalSize += fs.statSync(path.join(repoPath, file)).size; } catch(e){}
    });
    return totalSize;
};

// === 頁面路由 (分開的 HTML) ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/pages/index.html')));
app.get('/create', (req, res) => res.sendFile(path.join(__dirname, 'public/pages/create.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/pages/login.html')));
app.get('/dashboard', (req, res) => {
    // 簡單防護：如果沒 cookie 直接踢回首頁 (前端還會再驗證一次)
    if(!req.cookies.token || !sessions[req.cookies.token]) return res.redirect('/login');
    res.sendFile(path.join(__dirname, 'public/pages/dashboard.html'));
});

// === 安全驗證 Middleware ===
const verifySignature = (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token || !sessions[token]) {
            console.log('[AUTH FAIL] No Session');
            return res.status(401).json({ error: 'ACCESS DENIED: Invalid Session' });
        }

        const session = sessions[token];
        const clientTs = req.headers['x-timestamp'];
        const clientSign = req.headers['x-signature'];
        
        // 1. 驗證時間戳
        const now = Date.now();
        if (!clientTs || Math.abs(now - parseInt(clientTs)) > 30000) {
            console.log('[AUTH FAIL] Timestamp Replay');
            return res.status(403).json({ error: 'SECURITY ALERT: Replay Attack' });
        }

        // 2. 驗證簽名
        // 不驗證 Multipart (上傳檔案) 的 Body 簽名，只驗證 Timestamp
        if (!req.is('multipart/form-data')) {
            let payload = clientTs;
            
            // 關鍵：後端必須用跟前端一樣的方式重建字串
            // 如果 Body 不是空的，我們假設它是一個 JSON Object，轉回字串
            if (req.method !== 'GET' && Object.keys(req.body).length > 0) {
                 payload += JSON.stringify(req.body);
            }
            
            const serverSign = crypto.createHmac('sha256', session.signingKey).update(payload).digest('hex');

            if (clientSign !== serverSign) {
                console.log('[AUTH FAIL] Signature Mismatch');
                console.log('Server Expected:', serverSign);
                console.log('Client Sent:', clientSign);
                return res.status(403).json({ error: 'SECURITY ALERT: Signature Mismatch' });
            }
        }

        req.user = session;
        next();
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Auth Error' });
    }
};

// === API 路由 ===

app.post('/api/create', async (req, res) => {
    const { repoName, password } = req.body;
    if(!repoName || !password) return res.status(400).json({error: 'Missing Data'});
    
    const db = getDB();
    if (db.repos[repoName]) return res.status(400).json({ error: 'Repo Exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    db.repos[repoName] = { password: hashedPassword, isPublic: false, created: Date.now() };
    saveDB(db);
    fs.ensureDirSync(path.join(STORAGE_DIR, repoName));

    res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
    const { repoName, password } = req.body;
    const db = getDB();
    const repo = db.repos[repoName];

    if (!repo) return res.status(404).json({ error: 'Repo Not Found' });

    const match = await bcrypt.compare(password, repo.password);
    if (!match) return res.status(401).json({ error: 'Wrong Password' });

    const token = crypto.randomUUID();
    const signingKey = crypto.randomBytes(32).toString('hex');
    
    sessions[token] = { repoName, signingKey, expires: Date.now() + SESSION_TTL };

    // 設置 Cookie
    res.cookie('token', token, { httpOnly: true, secure: false }); // Render 上改 true
    res.json({ success: true, signingKey, repoName });
});

app.post('/api/logout', (req, res) => {
    const token = req.cookies.token;
    if(sessions[token]) delete sessions[token];
    res.clearCookie('token');
    res.json({ success: true });
});

// 取得 Repo 資訊
app.get('/api/repo', verifySignature, (req, res) => {
    const repoName = req.user.repoName;
    const db = getDB();
    const files = fs.readdirSync(path.join(STORAGE_DIR, repoName));
    const size = getRepoSize(repoName);
    
    res.json({
        files,
        size,
        maxSize: MAX_QUOTA,
        isPublic: db.repos[repoName].isPublic
    });
});

// 修改設定
app.post('/api/settings', verifySignature, (req, res) => {
    const db = getDB();
    db.repos[req.user.repoName].isPublic = req.body.isPublic;
    saveDB(db);
    res.json({ success: true });
});

// 刪除 Repo
app.delete('/api/repo', verifySignature, (req, res) => {
    const repoName = req.user.repoName;
    const db = getDB();
    delete db.repos[repoName];
    saveDB(db);
    fs.removeSync(path.join(STORAGE_DIR, repoName));
    delete sessions[req.cookies.token];
    res.clearCookie('token');
    res.json({ success: true });
});

// 檔案操作
app.post('/api/file/save', verifySignature, (req, res) => {
    const { filename, content } = req.body;
    const repoName = req.user.repoName;
    
    if (getRepoSize(repoName) + content.length > MAX_QUOTA) return res.status(400).json({ error: 'Quota Full' });

    fs.writeFileSync(path.join(STORAGE_DIR, repoName, filename), content);
    res.json({ success: true });
});

app.post('/api/file/upload', verifySignature, upload.single('file'), (req, res) => {
    const repoName = req.user.repoName;
    if(!req.file) return res.status(400).json({error: 'No File'});
    
    if (getRepoSize(repoName) + req.file.size > MAX_QUOTA) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Quota Full' });
    }

    fs.moveSync(req.file.path, path.join(STORAGE_DIR, repoName, req.file.originalname), { overwrite: true });
    res.json({ success: true });
});

app.delete('/api/file/:filename', verifySignature, (req, res) => {
    const p = path.join(STORAGE_DIR, req.user.repoName, req.params.filename);
    if(fs.existsSync(p)) fs.unlinkSync(p);
    res.json({ success: true });
});

// === 公開訪問 / 原始碼檢視 ===
app.get('/:repoName', (req, res) => {
    const { repoName } = req.params;
    const db = getDB();
    const repo = db.repos[repoName];
    
    // 檢查權限 (Cookie 或 Public)
    const token = req.cookies.token;
    const isOwner = token && sessions[token] && sessions[token].repoName === repoName;

    if (!repo) return res.status(404).send('REPO NOT FOUND');
    if (!repo.isPublic && !isOwner) return res.status(403).send('ACCESS DENIED (PRIVATE)');

    const files = fs.readdirSync(path.join(STORAGE_DIR, repoName));
    
    let html = `<body style="background:black;color:#0f0;font-family:monospace"><h1>Index of /${repoName}</h1><hr>`;
    html += `<a style="color:white" href="/">[HOME]</a><br><br>`;
    files.forEach(f => {
        html += `<a style="color:#0f0" href="/${repoName}/${f}">${f}</a><br>`;
    });
    res.send(html);
});

app.get('/:repoName/:fileName', (req, res) => {
    const { repoName, fileName } = req.params;
    const db = getDB();
    const repo = db.repos[repoName];
    
    const token = req.cookies.token;
    const isOwner = token && sessions[token] && sessions[token].repoName === repoName;

    if (!repo || (!repo.isPublic && !isOwner)) return res.status(403).send('ACCESS DENIED');
    
    const filePath = path.join(STORAGE_DIR, repoName, fileName);
    if (!fs.existsSync(filePath)) return res.status(404).send('Not Found');

    const mimeType = mime.lookup(filePath);
    if (mimeType && mimeType.startsWith('image/')) {
        res.setHeader('Content-Type', mimeType);
    } else {
        res.setHeader('Content-Type', 'text/plain; charset=utf-8'); // 強制原始碼
    }
    res.sendFile(path.resolve(filePath));
});

app.listen(PORT, () => console.log(`SYSTEM ONLINE PORT ${PORT}`));
