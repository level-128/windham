// Windham Web — Worker-based streaming disk browser

// ── Browser capability check ────────────────────────────────
function browserSupported() {
    var missing = [];
    if (typeof SharedArrayBuffer === 'undefined')
        missing.push('SharedArrayBuffer (needs COOP/COEP headers)');
    if (typeof Atomics === 'undefined')
        missing.push('Atomics');
    if (typeof window.showOpenFilePicker !== 'function')
        missing.push('File System Access API');
    if (typeof Worker === 'undefined')
        missing.push('Web Workers');
    return missing;
}
var _browserIssues = browserSupported();

const $ = s => document.querySelector(s);

var _worker = null;
var _workerReady = false;
var _shellReady = false;
var _cwd = '/';
var _fsType = '';
var _fileTree = { dirs: [], files: [] };
var _historyCwd = ['/'];
var _historyIdx = 0;
var _lastError = '';
var _stdoutAcc = '';
var _pendingCmd = null;

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

// ── Worker init ───────────────────────────────────────────────
var _stdinWake = null;
var _stdinWake = null;

// ── Worker init (runs on page load) ─────────────────────────
(function() {
    if (_browserIssues.length > 0) {
        $('#status').textContent = 'Browser not supported';
        $('#openBtn').disabled = true;
        showError('Browser not supported',
            'Your browser is missing required APIs:\n\u2022 ' +
            _browserIssues.join('\n\u2022 ') +
            '\n\nUse Chrome 86+ or Edge 86+ for full support.');
        return;
    }
    console.log('[app] starting, creating Worker');
    $('#status').textContent = 'Loading Worker...';
    _worker = new Worker('worker.js?v=2');
    _worker.onerror = function(e) {
        console.error('[app] Worker error:', e);
        showError('Worker Crashed', e.message || 'Unknown error');
    };
    _worker.onmessage = function(e) {
        console.log('[app] worker message:', e.data.type);
        var d = e.data;
        switch (d.type) {
        case 'loaded':
            console.log('[app] Worker loaded');
            _workerReady = true;
            $('#status').textContent = 'Ready';
            break;
        case 'sabs':
            _stdinWake = new Int32Array(d.stdinSab);
            break;
        case 'ready':
            $('#status').textContent = 'Disk mounted';
            break;
        case 'error':
            showError('Worker Error', d.msg);
            break;
        case 'stdout':
            handleStdout(d.text);
            break;
        case 'stderr':
            _lastError = d.text;
            if (_pendingCmd) { _pendingCmd.reject(d.text); _pendingCmd = null; }
            break;
        }
    };
})();

// ── stdout handler ────────────────────────────────────────────
function handleStdout(text) {
    if (text == null) return;
    console.log('[stdout]', text);
    if (text.indexOf('fat:') === 0) {
        var ci = text.indexOf(':'), gi = text.indexOf('>');
        if (ci > 0 && gi > ci) _cwd = text.substring(ci + 1, gi).trim();
        _shellReady = true;
        console.log('[app] shellReady set to true, pendingCmd=', !!_pendingCmd);
        if (_pendingCmd) {
            var r = _pendingCmd.resolve;
            var out = _stdoutAcc;
            _pendingCmd = null;
            _stdoutAcc = '';
            r(out);
        }
        return;
    }
    if (text.indexOf('Filesystem type:') === 0) {
        _fsType = text.split(':')[1].trim();
        $('#fsInfo').textContent = _fsType;
        $('#stateRow').style.display = 'flex';
        $('#mainLayout').style.display = 'flex';
        return;
    }
    if (/^\s*ERROR/i.test(text)) _lastError = text;
    _stdoutAcc += text + '\n';
    if (_stdoutAcc.length > 131072) _stdoutAcc = _stdoutAcc.slice(-65536);
}

// ── Shell commands ────────────────────────────────────────────
function shellCmd(cmd) {
    console.log('[app] shellCmd:', cmd, 'worker:', !!_worker);
    return new Promise(function(resolve, reject) {
        _lastError = '';
        _stdoutAcc = '';
        _pendingCmd = { resolve: resolve, reject: reject };
        try {
            _worker.postMessage({ type: 'cmd-queue', text: cmd + '\n' });
            console.log('[app] shellCmd: posted cmd-queue to worker');
        } catch(e) {
            console.error('[app] shellCmd: postMessage failed', e);
            reject(e);
        }
    });
}

function parseLs(output) {
    var r = { dirs: [], files: [] };
    var lines = output.split('\n');
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line.trim()) continue;
        var parts = line.split('\t');
        if (parts.length < 3) continue;
        var type = parts[0], size = parts[1], name = parts[2];
        if (name === '.' || name === '..') continue;
        if (type === 'd') r.dirs.push({ name: name, size: 0 });
        else if (type === 'f') r.files.push({ name: name, size: parseInt(size) || 0 });
    }
    return r;
}

function renderTree() {
    var el = $('#fileTree');
    el.innerHTML = '';
    if (_cwd !== '/') el.appendChild(makeItem('..', '..', 0, 'dir', function() { cd('..'); }));
    for (var i = 0; i < _fileTree.dirs.length; i++) (function(n){ el.appendChild(makeItem('D', n, 0, 'dir', function(){ cd(n); })); })(_fileTree.dirs[i].name);
    for (var i = 0; i < _fileTree.files.length; i++) (function(n,s){ el.appendChild(makeItem('F', n, s, '', function(){ previewFile(n, s); })); })(_fileTree.files[i].name, _fileTree.files[i].size);
    $('#breadcrumb').textContent = _cwd;
    $('#fileCount').textContent = _fileTree.dirs.length + ' dirs, ' + _fileTree.files.length + ' files';
}

function makeItem(icon, name, size, cls, onclick) {
    var d = document.createElement('div');
    d.className = 'tree-item ' + cls;
    d.innerHTML = '<span class="icon">' + icon + '</span><span class="name">' + esc(name) + '</span><span class="size">' + (size > 0 ? fmtSize(size) : '') + '</span><span class="dl" title="Download">DL</span>';
    d.onclick = onclick;
    var dl = d.querySelector('.dl');
    if (dl && cls !== 'dir') dl.onclick = function(e) { e.stopPropagation(); exportFile(name); };
    return d;
}

async function cd(dir) {
    await shellCmd(dir === '..' ? 'cd ..' : 'cd ' + dir);
    if (_lastError) { showError('cd Failed', _lastError); return; }
    _historyCwd = _historyCwd.slice(0, _historyIdx + 1);
    _historyCwd.push(_cwd);
    _historyIdx = _historyCwd.length - 1;
    updateNavBtns();
    await refresh();
}
async function navBack() { if (_historyIdx > 0) { _historyIdx--; await shellCmd('cd ' + _historyCwd[_historyIdx]); await refresh(); } }
async function navFwd() { if (_historyIdx < _historyCwd.length - 1) { _historyIdx++; await shellCmd('cd ' + _historyCwd[_historyIdx]); await refresh(); } }
function updateNavBtns() { $('#navBack').disabled = _historyIdx <= 0; $('#navFwd').disabled = _historyIdx >= _historyCwd.length - 1; }

async function refresh() {
    var output = await shellCmd('ls -p');
    if (_lastError) { showError('ls Failed', _lastError); return; }
    _fileTree = parseLs(output);
    renderTree();
    $('#status').textContent = 'Mounted ' + _fsType;
}

async function exportFile(name) {
    var fpath = _cwd + '/' + name;
    await shellCmd('export ' + fpath + ' /tmp/x');
    // export uses virtual FS — since we don't use it for disk I/O,
    // this path won't work with streaming. For now, notify the user.
    showError('Export', 'Export not yet supported with streaming I/O.');
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
    console.log('[app] openDisk called, workerReady=', _workerReady);
    var pass = $('#passInput').value;
    if (!pass) return;
    if (!_workerReady) { showError('Worker not ready', 'The WebAssembly Worker has not loaded yet.'); return; }

    $('#openBtn').disabled = true;
    $('#loadingArea').style.display = 'flex';
    $('#infoSection').style.display = 'none';
    $('#status').textContent = 'Selecting disk...';

    var handle;
    try {
        [handle] = await window.showOpenFilePicker({
            types: [{description: 'Disk images', accept: {'application/octet-stream': ['.img','.bin','.raw']}}]
        });
    } catch(e) {
        $('#openBtn').disabled = false;
        $('#status').textContent = 'Ready';
        showError('No file selected', 'Use the file picker to select a disk image.');
        return;
    }

    $('#status').textContent = 'Loading disk...';
    var file = await handle.getFile();
    var buf = await file.arrayBuffer();

    // Send disk image to Worker's virtual FS
    _worker.postMessage({ type: 'setup-fs', diskSize: file.size, diskData: new Uint8Array(buf) }, [buf]);
    // Wait for FS setup to complete
    await new Promise(function(r) {
        var orig = _worker.onmessage;
        _worker.onmessage = function(e) {
            if (e.data.type === 'ready') { _worker.onmessage = orig; r(); }
            else if (orig) orig(e);
        };
    });

    $('#loadingArea').style.display = 'none';
    $('#status').textContent = 'Unlocking...';

    // Call main in the Worker
    _worker.postMessage({ type: 'callMain', args: ['Open', '/disk.img', '--key', pass] });
    waitForShell(0);
}

function waitForShell(attempts) {
    if (_shellReady) {
        console.log('[app] shellReady, calling refresh');
        $('#toolbar').style.display = 'flex';
        _historyCwd = ['/']; _historyIdx = 0;
        updateNavBtns();
        if (_fsType) {
            $('#fsInfo').textContent = _fsType;
            $('#stateRow').style.display = 'flex';
            $('#mainLayout').style.display = 'flex';
        }
        refresh();
        return;
    }
    if (_lastError) { showError('Unlock Failed', _lastError); return; }
    if (attempts > 300) { showError('Timeout', 'Unlock took too long.'); return; }
    if (attempts % 10 === 0) $('#status').textContent = 'Waiting for shell... ' + (attempts/10).toFixed(0) + 's';
    setTimeout(function() { waitForShell(attempts + 1); }, 100);
}

// ── Events ─────────────────────────────────────────────────────
$('#passInput').oninput   = function() { $('#openBtn').disabled = !this.value; };
$('#passInput').onkeydown = function(e) { if (e.key === 'Enter') openDisk(); };
$('#openBtn').onclick     = openDisk;
$('#navBack').onclick     = navBack;
$('#navFwd').onclick      = navFwd;
$('#refreshBtn').onclick  = refresh;
$('#closeBtn').onclick    = closeDisk;

function closeDisk() {
    _shellReady = false; _cwd = '/'; _fsType = '';
    _fileTree = { dirs: [], files: [] };
    _historyCwd = ['/']; _historyIdx = 0;
    $('#mainLayout').style.display = 'none'; $('#stateRow').style.display = 'none';
    $('#previewPanel').style.display = 'none'; $('#toolbar').style.display = 'none';
    $('#fileTree').innerHTML = ''; $('#status').textContent = 'Ready';
    $('#openBtn').disabled = false;
    if (_worker) { _worker.terminate(); _worker = null; _workerReady = false; }
    location.reload();
}
