// Windham Web — WASM encrypted disk browser
// Uses ASYNCIFY + Module.stdin callback for interactive shell.

const $ = s => document.querySelector(s);

// ── ASYNCIFY stdin ────────────────────────────────────────────
let stdinWakeup = null;
let stdinChars  = '';

// ── Shell state ───────────────────────────────────────────────
let stdoutAcc   = '';
let shellReady  = false;
let cwd         = '/';
let fsType      = '';
let fileTree    = { dirs: [], files: [] };
let pendingCmd  = null;   // { resolve } — promise for current command

// ── Helpers ───────────────────────────────────────────────────
function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
    return (n/1073741824).toFixed(1) + ' GB';
}
function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function log(type, text) {
    const d = document.createElement('div');
    d.className = type;
    d.textContent = text;
    $('#logBody').appendChild(d);
    $('#logBody').scrollTop = $('#logBody').scrollHeight;
}

// ── Emscripten Module (merge into existing) ────────────────────
Module['noInitialRun'] = true;
Module['noExitRuntime'] = true;

// stdout
Module['print'] = function(text) {
        // Detect shell prompt
        if (text.indexOf('fat:') === 0) {
            const i = text.indexOf('>');
            if (i > 0) cwd = text.substring(text.indexOf(':')+1, i).trim();
            shellReady = true;
            if (pendingCmd) {
                const r = pendingCmd.resolve;
                pendingCmd = null;
                stdoutAcc = '';
                r();
            }
            return;
        }

        // Detect FS type
        if (text.indexOf('Filesystem type:') === 0) {
            fsType = text.split(':')[1].trim();
            $('#fsInfo').textContent = fsType;
            $('#stateRow').style.display = 'flex';
            $('#mainLayout').style.display = 'flex';
            return;
        }

        stdoutAcc += text + '\n';
        if (text.trim()) log('out', text);
};

// stderr
Module['printErr'] = function(text) {
    log('err', text);
};

// ASYNCIFY stdin — yields until we wake it
Module['stdin'] = function() {
    return Asyncify.handleSleep(function(wakeUp) {
        stdinWakeup = wakeUp;
    });
};

Module['onRuntimeInitialized'] = function() {
    $('#status').textContent = 'Ready';
    $('#openBtn').disabled = false;
};

// ── Feed a command to stdin (ASYNCIFY-safe) ───────────────────
function shellCmd(cmd) {
    return new Promise(function(resolve) {
        log('cmd', cmd);
        pendingCmd = { resolve: resolve };
        feedChars(cmd + '\n');
    });
}

function feedChars(s) {
    stdinChars += s;
    pumpStdin();
}

function pumpStdin() {
    while (stdinChars.length > 0 && stdinWakeup) {
        const ch = stdinChars.charCodeAt(0);
        stdinChars = stdinChars.slice(1);
        const w = stdinWakeup;
        stdinWakeup = null;
        w(ch);   // wake ASYNCIFY with next char
    }
}

// ── Parse ls -p output ────────────────────────────────────────
function parseLs() {
    const result = { dirs: [], files: [] };
    const lines = stdoutAcc.split('\n');
    for (const line of lines) {
        if (!line.trim()) continue;
        const parts = line.split('\t');
        if (parts.length < 3) continue;
        const [type, size, name] = parts;
        if (name === '.' || name === '..') continue;
        if (type === 'd') result.dirs.push({ name, size: 0 });
        else if (type === 'f') result.files.push({ name, size: parseInt(size) || 0 });
    }
    return result;
}

// ── Render file tree ──────────────────────────────────────────
function renderTree() {
    const el = $('#fileTree');
    el.innerHTML = '';

    if (cwd !== '/') {
        const d = makeItem('📁', '..', 0, 'dir', function() { cd('..'); });
        el.appendChild(d);
    }

    for (const e of fileTree.dirs) el.appendChild(dirItem(e.name));
    for (const e of fileTree.files) el.appendChild(fileItem(e.name, e.size));

    $('#breadcrumb').textContent = cwd;
}

function makeItem(icon, name, size, cls, onclick) {
    const d = document.createElement('div');
    d.className = 'tree-item ' + cls;
    d.innerHTML =
        '<span class="icon">' + icon + '</span>' +
        '<span class="name">' + esc(name) + '</span>' +
        (size > 0 ? '<span class="size">' + fmtSize(size) + '</span>' : '') +
        '<span class="dl">⬇</span>';
    d.onclick = onclick;
    return d;
}

function dirItem(name) {
    const d = makeItem('📁', name, 0, 'dir', function() { cd(name); });
    return d;
}

function fileItem(name, size) {
    const icon = /\.(jpg|png|gif|webp|bmp|svg)$/i.test(name) ? '🖼' :
                 /\.(txt|md|log|cfg|ini|json|xml)$/i.test(name) ? '📄' :
                 /\.(zip|tar|gz|7z|rar)$/i.test(name) ? '📦' : '📎';
    const d = makeItem(icon, name, size, '', null);
    d.querySelector('.dl').onclick = function(e) {
        e.stopPropagation();
        exportFile(name);
    };
    return d;
}

// ── Actions ────────────────────────────────────────────────────
async function cd(dir) {
    await shellCmd(dir === '..' ? 'cd ..' : 'cd ' + dir);
    await ls();
}

async function ls() {
    await shellCmd('ls -p');
    fileTree = parseLs();
    renderTree();
}

async function exportFile(name) {
    const fpath = cwd + '/' + name;
    log('cmd', 'export ' + fpath);
    try { Module.FS.unlink('/tmp/x'); } catch(e) {}
    await shellCmd('export ' + fpath + ' /tmp/x');
    try {
        const data = Module.FS.readFile('/tmp/x');
        const url  = URL.createObjectURL(new Blob([data]));
        const a    = document.createElement('a');
        a.href = url; a.download = name; a.click();
        URL.revokeObjectURL(url);
        Module.FS.unlink('/tmp/x');
    } catch(e) { log('err', 'Export: ' + e.message); }
}

// ── Open disk ──────────────────────────────────────────────────
async function openDisk() {
    const file = $('#fileInput').files[0];
    const pass = $('#passInput').value;
    if (!file || !pass) return;

    $('#openBtn').disabled = true;
    $('#loadingArea').style.display = 'flex';
    $('#status').textContent = 'Reading disk...';

    const buf = await file.arrayBuffer();
    Module.FS.writeFile('/disk.img', new Uint8Array(buf));
    Module.FS.writeFile('/password', pass);
    log('out', file.name + ' (' + fmtSize(buf.byteLength) + ')');

    $('#loadingArea').style.display = 'none';
    $('#status').textContent = 'Deriving key...';

    // callMain with ASYNCIFY returns immediately
    Module.callMain(['Open', '/disk.img', '--key-file', '/password', '--driver', 'ff']);

    waitForShell();
}

function waitForShell() {
    if (shellReady) {
        $('#status').textContent = 'Mounted · ' + fsType;
        ls();
        return;
    }
    setTimeout(waitForShell, 100);
}

// ── Events ─────────────────────────────────────────────────────
$('#fileInput').onchange = checkForm;
$('#passInput').oninput   = checkForm;
$('#openBtn').onclick     = openDisk;

function checkForm() {
    $('#openBtn').disabled = !($('#fileInput').files.length && $('#passInput').value);
}
