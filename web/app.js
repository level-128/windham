// Windham Web — File browser UI
// All I/O callbacks and shared state are on the Module object,
// set up in index.html's inline script before windham.js loads.
var Windham = {};
const $ = s => document.querySelector(s);

// ── Error modal ───────────────────────────────────────────────
function showError(title, msg) {
    $('#errTitle').textContent = title;
    $('#errBody').textContent  = msg;
    $('#errorModal').style.display = 'flex';
}
function hideError() { $('#errorModal').style.display = 'none'; }
$('#errorClose').onclick = hideError;
$('#errorModal').onclick = function(e) { if (e.target === this) hideError(); };

// ── Helpers ───────────────────────────────────────────────────
function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
    return (n/1073741824).toFixed(1) + ' GB';
}
function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Shared state (initialized by inline script, consumed here)
Module._cwd = Module._cwd || '/';
Module._fsType = Module._fsType || '';
Module._shellReady = Module._shellReady || false;

var _fileTree = { dirs: [], files: [] };
var _historyCwd = ['/'];
var _historyIdx = 0;

Windham.onReady = function() {
    $('#status').textContent = 'Ready';
    $('#openBtn').disabled = false;
};

// ── Feed a command to stdin ───────────────────────────────────
function shellCmd(cmd) {
    return new Promise(function(resolve) {
        Module._lastError = '';
        Module._stdoutAcc = '';
        Module._pendingCmd = { resolve: resolve };
        Module.FS.writeFile('/cmd_queue', cmd + '\n');
    });
}

// ── Parse ls -p output ────────────────────────────────────────
function parseLs(output) {
    var result = { dirs: [], files: [] };
    var lines = output.split('\n');
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line.trim()) continue;
        var parts = line.split('\t');
        if (parts.length < 3) continue;
        var type = parts[0], size = parts[1], name = parts[2];
        if (name === '.' || name === '..') continue;
        if (type === 'd') result.dirs.push({ name: name, size: 0 });
        else if (type === 'f') result.files.push({ name: name, size: parseInt(size) || 0 });
    }
    return result;
}

// ── Render file tree ──────────────────────────────────────────
function renderTree() {
    var el = $('#fileTree');
    el.innerHTML = '';
    var cwd = Module._cwd;

    if (cwd !== '/') el.appendChild(makeItem('📂', '..', 0, 'dir', function() { cd('..'); }));

    for (var i = 0; i < _fileTree.dirs.length; i++) (function(n){ el.appendChild(makeItem('📁', n, 0, 'dir', function(){ cd(n); })); })(_fileTree.dirs[i].name);
    for (var i = 0; i < _fileTree.files.length; i++) (function(n,s){ el.appendChild(makeItem(iconFor(n), n, s, '', function(){ previewFile(n, s); })); })(_fileTree.files[i].name, _fileTree.files[i].size);

    $('#breadcrumb').textContent = cwd;
    $('#fileCount').textContent = _fileTree.dirs.length + ' dirs, ' + _fileTree.files.length + ' files';
}

function iconFor(name) {
    return /\.(jpg|png|gif|webp|bmp|svg|ico)$/i.test(name) ? '🖼' :
           /\.(txt|md|log|cfg|ini|json|xml|yaml|yml|toml)$/i.test(name) ? '📄' :
           /\.(zip|tar|gz|7z|rar|lz|xz)$/i.test(name) ? '📦' :
           /\.(mp3|wav|flac|ogg|aac)$/i.test(name) ? '🎵' :
           /\.(mp4|mov|avi|mkv|webm)$/i.test(name) ? '🎬' : '📄';
}

function makeItem(icon, name, size, cls, onclick) {
    var d = document.createElement('div');
    d.className = 'tree-item ' + cls;
    d.innerHTML = '<span class="icon">' + icon + '</span>' +
        '<span class="name">' + esc(name) + '</span>' +
        '<span class="size">' + (size > 0 ? fmtSize(size) : '') + '</span>' +
        '<span class="dl" title="Download">⬇</span>';
    d.onclick = onclick;
    var dl = d.querySelector('.dl');
    if (dl && cls !== 'dir') dl.onclick = function(e) { e.stopPropagation(); exportFile(name); };
    return d;
}

// ── Actions ────────────────────────────────────────────────────
async function cd(dir) {
    await shellCmd(dir === '..' ? 'cd ..' : 'cd ' + dir);
    if (Module._lastError) { showError('cd Failed', Module._lastError); return; }
    _historyCwd = _historyCwd.slice(0, _historyIdx + 1);
    _historyCwd.push(Module._cwd);
    _historyIdx = _historyCwd.length - 1;
    updateNavBtns();
    await refresh();
}

async function navBack() {
    if (_historyIdx > 0) { _historyIdx--; await shellCmd('cd ' + _historyCwd[_historyIdx]); await refresh(); }
}
async function navFwd() {
    if (_historyIdx < _historyCwd.length - 1) { _historyIdx++; await shellCmd('cd ' + _historyCwd[_historyIdx]); await refresh(); }
}
function updateNavBtns() {
    $('#navBack').disabled = _historyIdx <= 0;
    $('#navFwd').disabled = _historyIdx >= _historyCwd.length - 1;
}

async function refresh() {
    var output = await shellCmd('ls -p');
    if (Module._lastError) { showError('ls Failed', Module._lastError); return; }
    _fileTree = parseLs(output);
    renderTree();
    $('#status').textContent = 'Mounted \u00b7 ' + Module._fsType;
}

async function exportFile(name) {
    var fpath = Module._cwd + '/' + name;
    $('#status').textContent = 'Exporting...';
    try { Module.FS.unlink('/tmp/x'); } catch(e) {}
    await shellCmd('export ' + fpath + ' /tmp/x');
    if (Module._lastError) { showError('Export Failed', Module._lastError); return; }
    try {
        var data = Module.FS.readFile('/tmp/x');
        var url = URL.createObjectURL(new Blob([data]));
        var a = document.createElement('a');
        a.href = url; a.download = name; a.click();
        URL.revokeObjectURL(url);
        Module.FS.unlink('/tmp/x');
    } catch(e) { showError('Export Failed', e.message); }
    $('#status').textContent = 'Mounted \u00b7 ' + Module._fsType;
}

function previewFile(name, size) {
    $('#previewName').textContent = name;
    $('#previewSize').textContent = fmtSize(size);
    $('#previewPanel').style.display = 'block';
}
function closePreview() { $('#previewPanel').style.display = 'none'; }
$('#previewClose').onclick = closePreview;

// ── Open disk ──────────────────────────────────────────────────
async function openDisk() {
    var file = $('#fileInput').files[0];
    var pass = $('#passInput').value;
    if (!file || !pass) return;

    $('#openBtn').disabled = true;
    $('#loadingArea').style.display = 'flex';
    $('#infoSection').style.display = 'none';
    $('#status').textContent = 'Reading disk...';

    var buf = await file.arrayBuffer();
    Module.FS.writeFile('/disk.img', new Uint8Array(buf));
    Module.FS.writeFile('/cmd_queue', new Uint8Array(0));

    $('#loadingArea').style.display = 'none';
    $('#status').textContent = 'Deriving key...';

    try {
        Module.callMain(['Open', '/disk.img', '--key', pass]);
    } catch(e) { showError('Unlock Failed', e.message||String(e)); $('#openBtn').disabled = false; return; }
    waitForShell(0);
}

function waitForShell(attempts) {
    if (Module._shellReady) {
        $('#toolbar').style.display = 'flex';
        _historyCwd = ['/']; _historyIdx = 0;
        updateNavBtns();
        if (Module._fsType) {
            $('#fsInfo').textContent = Module._fsType;
            $('#stateRow').style.display = 'flex';
            $('#mainLayout').style.display = 'flex';
        }
        refresh();
        return;
    }
    if (Module._lastError) { showError('Unlock Failed', Module._lastError); return; }
    if (attempts > 300) { showError('Timeout', 'Unlock took too long.'); return; }
    if (attempts % 10 === 0) $('#status').textContent = 'Waiting for shell... ' + (attempts/10).toFixed(0) + 's';
    setTimeout(function() { waitForShell(attempts + 1); }, 100);
}

// ── Events ─────────────────────────────────────────────────────
$('#fileInput').onchange = checkForm;
$('#passInput').oninput   = checkForm;
$('#passInput').onkeydown = function(e) { if (e.key === 'Enter') openDisk(); };
$('#openBtn').onclick     = openDisk;
$('#navBack').onclick     = navBack;
$('#navFwd').onclick      = navFwd;
$('#refreshBtn').onclick  = refresh;
$('#closeBtn').onclick    = closeDisk;

function checkForm() {
    $('#openBtn').disabled = !($('#fileInput').files.length && $('#passInput').value);
}

function closeDisk() {
    Module._shellReady = false;
    Module._cwd = '/';
    Module._fsType = '';
    _fileTree = { dirs: [], files: [] };
    _historyCwd = ['/']; _historyIdx = 0;
    $('#mainLayout').style.display = 'none';
    $('#stateRow').style.display = 'none';
    $('#previewPanel').style.display = 'none';
    $('#toolbar').style.display = 'none';
    $('#infoSection').style.display = '';
    $('#fileTree').innerHTML = '';
    $('#status').textContent = 'Ready';
    checkForm();
    location.reload();
}
