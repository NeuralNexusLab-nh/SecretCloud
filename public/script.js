// Global State
let signingKey = null;
let currentRepo = null;

// === CRYPTO UTILS (Native JS) ===
async function hmacSha256(keyHex, message) {
    const enc = new TextEncoder();
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    
    // Convert hex key to Uint8Array
    const keyBytes = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
    const key = await crypto.subtle.importKey("raw", keyBytes, algorithm, false, ["sign"]);
    const signature = await crypto.subtle.sign(algorithm.name, key, enc.encode(message));
    
    // Convert buffer to hex string
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// === API WRAPPER (Sign & Fetch) ===
async function secureFetch(url, method, body = null, isMultipart = false) {
    const headers = {};
    const timestamp = Date.now().toString();

    // Only sign if we have a key (logged in)
    if (signingKey) {
        headers['X-Timestamp'] = timestamp;
        
        // Simplified signature logic for demo (Body signing)
        let payload = timestamp;
        if (body && !isMultipart) {
            payload += JSON.stringify(body);
        }
        
        // Multipart signature is complex to implement purely in JS without reading the whole file stream
        // So for this demo, we trust session + timestamp for multipart, but sign everything else.
        if (!isMultipart) {
            const signature = await hmacSha256(signingKey, payload);
            headers['X-Signature'] = signature;
        }
    }

    const options = {
        method: method,
        headers: headers
    };

    if (body) {
        if (isMultipart) {
            options.body = body; // FormData
        } else {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
    }

    const response = await fetch(url, options);
    const data = await response.json();
    return { status: response.status, data };
}

// === UI LOGIC ===

function log(msg) {
    const term = document.getElementById('terminal-output');
    term.innerText = `> ${msg}`;
    term.classList.remove('highlight-action');
    void term.offsetWidth; // trigger reflow
    term.classList.add('highlight-action');
}

function showPage(pageId) {
    document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
    document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
    document.getElementById(`page-${pageId}`).classList.remove('hidden');
    document.getElementById(`page-${pageId}`).classList.add('active');
    log(`NAVIGATING TO... ${pageId.toUpperCase()}`);
}

// === ACTIONS ===

async function createRepo() {
    const name = document.getElementById('create-name').value;
    const pass = document.getElementById('create-pass').value;

    const res = await secureFetch('/api/create', 'POST', { repoName: name, password: pass });
    
    if (res.status === 200) {
        log('REPO CREATED. PLEASE LOGIN.');
        showPage('login');
    } else {
        log(`ERROR: ${res.data.error}`);
    }
}

async function loginRepo() {
    const name = document.getElementById('login-name').value;
    const pass = document.getElementById('login-pass').value;

    const res = await secureFetch('/api/login', 'POST', { repoName: name, password: pass });

    if (res.status === 200) {
        signingKey = res.data.signingKey; // Store key in memory ONLY
        currentRepo = res.data.repoName;
        log('ACCESS GRANTED. KEY EXCHANGE SUCCESSFUL.');
        document.getElementById('dash-repo-name').innerText = currentRepo;
        loadRepoInfo();
        showPage('dashboard');
    } else {
        log(`ACCESS DENIED: ${res.data.error}`);
    }
}

async function logout() {
    await secureFetch('/api/logout', 'POST');
    signingKey = null;
    currentRepo = null;
    showPage('home');
    log('DISCONNECTED.');
}

async function loadRepoInfo() {
    const res = await secureFetch('/api/repo', 'GET');
    if (res.status !== 200) return log('FAILED TO FETCH DATA');

    const { files, size, maxSize, isPublic } = res.data;
    
    // Update Stats
    document.getElementById('storage-usage').innerText = (size / (1024*1024)).toFixed(2) + " MB";
    document.getElementById('visibility-status').innerText = isPublic ? "PUBLIC" : "PRIVATE";
    document.getElementById('visibility-status').style.color = isPublic ? "orange" : "#0f0";

    // Update File List
    const list = document.getElementById('file-list');
    list.innerHTML = '';
    
    files.forEach(f => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span>
                <a href="/${currentRepo}/${f}" target="_blank">[ VIEW SOURCE ]</a>
                &nbsp; ${f}
            </span>
            <div>
                <button onclick="editFile('${f}')">EDIT</button>
                <button class="danger-btn" onclick="deleteFile('${f}')">DEL</button>
            </div>
        `;
        list.appendChild(li);
    });
}

async function toggleVisibility() {
    const currentTxt = document.getElementById('visibility-status').innerText;
    const newState = currentTxt === 'PRIVATE'; // Toggle
    
    const res = await secureFetch('/api/settings/visibility', 'POST', { isPublic: newState });
    if(res.status === 200) {
        log(res.data.message);
        loadRepoInfo();
    }
}

async function deleteRepo() {
    if(!confirm("WARNING: PERMANENTLY DELETE REPO? THIS CANNOT BE UNDONE.")) return;
    
    const res = await secureFetch('/api/repo', 'DELETE');
    if(res.status === 200) {
        alert("REPO DELETED.");
        location.reload();
    }
}

// === FILE OPERATIONS ===

async function createFile() {
    const filename = document.getElementById('new-filename').value;
    if(!filename) return log('FILENAME REQUIRED');
    
    // Save empty file
    const res = await secureFetch('/api/file/save', 'POST', { filename, content: '' });
    if(res.status === 200) {
        log(`FILE ${filename} CREATED.`);
        loadRepoInfo();
        editFile(filename);
    } else {
        log(res.data.error);
    }
}

async function uploadFile() {
    const input = document.getElementById('upload-input');
    if(input.files.length === 0) return log('NO FILE SELECTED');

    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);

    log('UPLOADING... PLEASE WAIT.');
    const res = await secureFetch('/api/file/upload', 'POST', formData, true);
    
    if(res.status === 200) {
        log('UPLOAD COMPLETE.');
        loadRepoInfo();
    } else {
        log(`UPLOAD FAILED: ${res.data.error}`);
    }
}

async function deleteFile(filename) {
    if(!confirm(`DELETE ${filename}?`)) return;

    const res = await secureFetch(`/api/file/${filename}`, 'DELETE');
    if(res.status === 200) {
        log(`FILE ${filename} DELETED.`);
        loadRepoInfo();
    }
}

// === WEB IDE ===

async function editFile(filename) {
    // Fetch content directly from public URL (since we are logged in, session cookie handles auth)
    const response = await fetch(`/${currentRepo}/${filename}`);
    const text = await response.text();
    
    document.getElementById('ide-filename').innerText = filename;
    document.getElementById('code-editor').value = text;
    
    showPage('ide');
}

async function saveFile() {
    const filename = document.getElementById('ide-filename').innerText;
    const content = document.getElementById('code-editor').value;
    const btn = document.getElementById('btn-save');

    // Animation
    btn.classList.add('highlight-action');
    setTimeout(() => btn.classList.remove('highlight-action'), 500);

    const res = await secureFetch('/api/file/save', 'POST', { filename, content });
    
    if(res.status === 200) {
        log(`FILE ${filename} SAVED.`);
    } else {
        log(`SAVE FAILED: ${res.data.error}`);
    }
}

function closeIde() {
    showPage('dashboard');
    loadRepoInfo();
}
