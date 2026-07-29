// Windham Web — sidebar-driven disk browser
// ── Browser capability check ────────────────────────────────
function browserSupported() {
    var missing = [];
    if (typeof SharedArrayBuffer === 'undefined')
        missing.push('SharedArrayBuffer (needs COOP/COEP headers)');
    if (typeof Atomics === 'undefined')
        missing.push('Atomics');
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
var _inError = false;
var _cachedPass = '';
var _cachedMasterKey = '';
var _shellExited = false;
var _pendingShellExit = null;
var _pendingMasterKey = null;
var _pendingBackupDone = null;
var _pendingAuxDone = null;

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
(function() {
    if (_browserIssues.length > 0) {
        $('#openBtn').disabled = true;
        showError('Browser not supported',
            'Your browser is missing required APIs:\n\u2022 ' +
            _browserIssues.join('\n\u2022 ') +
            '\n\nUse Chrome 86+ or Edge 86+ for full support.');
        return;
    }
    _worker = new Worker('worker.js?v=3');
    _worker.onerror = function(e) {
        showError('Worker Crashed', e.message || 'Unknown error');
    };
    _worker.onmessage = function(e) {
        var d = e.data;
        switch (d.type) {
        case 'loaded':
            _workerReady = true;
            break;
        case 'ready':
            _shellReady = false;
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
    if (text.indexOf('fat:') === 0) {
        var ci = text.indexOf(':'), gi = text.indexOf('>');
        if (ci > 0 && gi > ci) _cwd = text.substring(ci + 1, gi).trim();
        _shellReady = true;
        if (_pendingCmd) {
            var r = _pendingCmd.resolve, out = _stdoutAcc;
            _pendingCmd = null; _stdoutAcc = '';
            r(out);
        }
        return;
    }
    if (text.indexOf('Filesystem type:') === 0) {
        _fsType = text.split(':')[1].trim();
        $('#fsInfo').textContent = _fsType;
        return;
    }
    if (/^\s*ERROR/i.test(text)) { _lastError = text; _inError = true; }
    else if (_inError && /^\s*fat:/.test(text)) { _inError = false; }
    else if (_inError) { _lastError += '\n' + text; return; }
    if (text.indexOf('MK ') === 0) {
        _cachedMasterKey = text.substring(3).replace(/\s/g, '');
        if (_pendingMasterKey) { _pendingMasterKey(); _pendingMasterKey = null; }
        return;
    }
    if (text.indexOf('SHELL_EXITED') === 0) {
        _shellExited = true; _shellReady = false;
        if (_pendingShellExit) { _pendingShellExit(); _pendingShellExit = null; }
        if (_pendingCmd) { _pendingCmd.resolve(''); _pendingCmd = null; }
        return;
    }
    if (text.indexOf('BACKUP_DONE') === 0) {
        if (_pendingBackupDone) { _pendingBackupDone(); _pendingBackupDone = null; }
        return;
    }
    if (text.indexOf('DRYRUN_OK') === 0) {
        if (_pendingBackupDone) { _pendingBackupDone(); _pendingBackupDone = null; }
        return;
    }
    if (text.indexOf('AUXPROBE_OK') === 0) {
        if (_pendingAuxDone) { _pendingAuxDone(); _pendingAuxDone = null; }
        return;
    }
    _stdoutAcc += text + '\n';
    if (_stdoutAcc.length > 131072) _stdoutAcc = _stdoutAcc.slice(-65536);
}

// ── Shell commands ────────────────────────────────────────────
function shellCmd(cmd) {
    return new Promise(function(resolve, reject) {
        _lastError = ''; _stdoutAcc = ''; _inError = false;
        _pendingCmd = { resolve: resolve, reject: reject };
        try {
            _worker.postMessage({ type: 'cmd-queue', text: cmd + '\n' });
        } catch(e) { reject(e); }
    });
}

// ── Files tab ────────────────────────────────────────────────
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
    if (_cwd !== '/') el.appendChild(makeItem('📂', '..', 0, 'dir', function() { cd('..'); }));
    for (var i = 0; i < _fileTree.dirs.length; i++)
        (function(n){ el.appendChild(makeItem('📁', n, 0, 'dir', function(){ cd(n); })); })(_fileTree.dirs[i].name);
    for (var i = 0; i < _fileTree.files.length; i++)
        (function(n,s){ el.appendChild(makeItem('📄', n, s, '', function(){ previewFile(n, s); })); })(_fileTree.files[i].name, _fileTree.files[i].size);
    $('#breadcrumb').textContent = _cwd;
    $('#fileCount').textContent = _fileTree.dirs.length + ' dirs, ' + _fileTree.files.length + ' files';
}

function makeItem(icon, name, size, cls, onclick) {
    var d = document.createElement('div');
    d.className = 'tree-item ' + cls;
    d.innerHTML = '<span class="icon">' + icon + '</span><span class="name">' + esc(name) + '</span><span class="size">' + (size > 0 ? fmtSize(size) : '') + '</span><span class="dl" title="Download">⬇</span>';
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
}

async function exportFile(name) {
    var fpath = _cwd + '/' + name;
    await shellCmd('export ' + fpath + ' /tmp/x');
    showError('Export', 'Export not yet supported with streaming I/O.');
}

function previewFile(name, size) {
    $('#previewName').textContent = name;
    $('#previewSize').textContent = fmtSize(size);
    $('#previewPanel').style.display = 'block';
}
function closePreview() { $('#previewPanel').style.display = 'none'; }
$('#previewClose').onclick = closePreview;

// ── Backup tab ──────────────────────────────────────────────
async function backupFold() {
    var statusEl = $('#buStatus');
    if (!_cachedPass) { statusEl.textContent = 'No passphrase available. Re-open the disk first.'; return; }
    try {
        statusEl.textContent = 'Exiting shell...';
        _shellExited = false;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');

        statusEl.textContent = 'Creating fold backup...';
        var backupDone = new Promise(function(r) { _pendingBackupDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Backup', '--fold', '--to', '/tmp/fold.bu', '--key', _cachedPass, '/disk.img'] });
        await Promise.race([backupDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('backup timeout')); }, 30000); })]);

        statusEl.textContent = 'Reading backup...';
        var fileData = await new Promise(function(resolve, reject) {
            var orig = _worker.onmessage;
            _worker.onmessage = function(e) {
                if (e.data.type === 'file-data' && e.data.path === '/tmp/fold.bu') {
                    _worker.onmessage = orig; resolve(e.data.data);
                } else if (e.data.type === 'file-error' && e.data.path === '/tmp/fold.bu') {
                    _worker.onmessage = orig; reject(new Error(e.data.msg));
                } else if (orig) orig(e);
            };
            _worker.postMessage({ type: 'read-file', path: '/tmp/fold.bu' });
        });

        var blob = new Blob([fileData], { type: 'application/octet-stream' });
        var link = document.createElement('a');
        link.download = 'windham-fold.bu';
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        statusEl.textContent = 'Backup downloaded. Remounting...';

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = 'Backup complete.';
    } catch(e) {
        statusEl.textContent = 'Backup failed: ' + e;
        showError('Backup Failed', String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}

$('#buDownloadBtn').onclick = backupFold;

async function showQr() {
    var statusEl = $('#buStatus');
    var canvasEl = $('#qrCanvas');
    if (!_cachedPass) { statusEl.textContent = 'No passphrase available.'; return; }
    try {
        statusEl.textContent = 'Exiting shell...';
        _shellExited = false;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');

        statusEl.textContent = 'Generating QR code...';
        _stdoutAcc = '';
        var backupDone = new Promise(function(r) { _pendingBackupDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Backup', '--qrcode=/tmp/qr.bmp', '--to', '/tmp/fold.bu', '--key', _cachedPass, '/disk.img'] });
        await Promise.race([backupDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('timeout')); }, 30000); })]);

        statusEl.textContent = 'Reading QR image...';
        var bmpData = await new Promise(function(resolve, reject) {
            var orig = _worker.onmessage;
            _worker.onmessage = function(e) {
                if (e.data.type === 'file-data' && e.data.path === '/tmp/qr.bmp') {
                    _worker.onmessage = orig; resolve(e.data.data);
                } else if (e.data.type === 'file-error' && e.data.path === '/tmp/qr.bmp') {
                    _worker.onmessage = orig; reject(new Error(e.data.msg));
                } else if (orig) orig(e);
            };
            _worker.postMessage({ type: 'read-file', path: '/tmp/qr.bmp' });
        });

        var blob = new Blob([bmpData], { type: 'image/bmp' });
        var img = await createImageBitmap(blob);
        canvasEl.width = img.width; canvasEl.height = img.height;
        canvasEl.style.display = 'block';
        var ctx = canvasEl.getContext('2d');
        ctx.drawImage(img, 0, 0);
        img.close();
        statusEl.textContent = 'QR code generated.';

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    } catch(e) {
        statusEl.textContent = 'QR failed: ' + e;
        showError('QR Failed', String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}
$('#buQrBtn').onclick = showQr;

// ── Aux tab ──────────────────────────────────────────────────
async function loadAux() {
    var statusEl = $('#auxStatus');
    var outputEl = $('#auxOutput');
    outputEl.textContent = 'Loading...';
    if (!_cachedPass) { outputEl.textContent = 'No passphrase available.'; return; }
    try {
        _shellExited = false;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');
        _shellReady = false;

        _stdoutAcc = '';
        var auxDone = new Promise(function(r) { _pendingAuxDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Aux', '--aux-probe', '--key', _cachedPass, '/disk.img'] });
        await Promise.race([auxDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('aux timeout')); }, 30000); })]);

        var lines = _stdoutAcc.split('\n');
        var filtered = [];
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (l.indexOf('AUXPROBE_OK') >= 0 || l.indexOf('MK ') === 0) continue;
            filtered.push(l);
        }
        outputEl.textContent = filtered.join('\n').trim() || 'No aux entries found.';

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = '';
    } catch(e) {
        outputEl.textContent = 'Failed: ' + e;
        showError('Aux Failed', String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}

// ── Metadata tab ────────────────────────────────────────────
async function loadMeta() {
    var statusEl = $('#metaStatus');
    if (!_cachedMasterKey) { statusEl.textContent = 'No master key available.'; return; }
    try {
        _shellExited = false;
        _pendingMasterKey = null;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');
        _shellReady = false;

        _stdoutAcc = '';
        var metaDone = new Promise(function(r) { _pendingBackupDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Open', '--dry-run', '--master-key', _cachedMasterKey, '/disk.img'] });
        await Promise.race([metaDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('timeout')); }, 30000); })]);

        var lines = _stdoutAcc.split('\n');
        var metaKV = [], slotBlocks = [], curSlot = null;
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].indexOf('\t') !== 0) continue;
            var raw = lines[i].replace(/\t/g, '').trim();
            if (/^Slot \d+$/.test(raw)) {
                curSlot = { num: parseInt(raw.split(' ')[1]), fields: [] };
                slotBlocks.push(curSlot);
            } else if (curSlot) {
                var ci = raw.indexOf(': ');
                if (ci > 0) curSlot.fields.push({ key: raw.substring(0, ci).trim(), val: raw.substring(ci + 1).trim() });
                else curSlot.fields.push({ key: '', val: raw });
            } else {
                var ci2 = raw.indexOf(': ');
                if (ci2 > 0) metaKV.push({ key: raw.substring(0, ci2).trim(), val: raw.substring(ci2 + 1).trim() });
                else metaKV.push({ key: raw, val: '' });
            }
        }

        var tbody = $('#metaTable');
        while (tbody.rows.length > 1) tbody.deleteRow(1);
        for (var mi = 0; mi < metaKV.length; mi++) {
            var tr = tbody.insertRow(); tr.style.borderBottom = 'none';
            var td = tr.insertCell(0); td.textContent = metaKV[mi].key; td.style.color = '#888';
            var td1 = tr.insertCell(1); td1.textContent = metaKV[mi].val;
        }
        var slotTbody = $('#slotTable');
        while (slotTbody.rows.length > 0) slotTbody.deleteRow(0);
        if (slotBlocks.length > 0) {
            var kdfMemKiB = [350, 1480, 6100, 22469, 61079, 166024, 451332,
                902702, 1805405, 3610810, 7221620, 14443240, 28886480,
                57772960, 115545920, 231091841, 462183682, 924367364,
                1848734729, 3697469458, 7394938916, 14789877832, 29579755664,
                59159511328, 118319022656, 236638045313];
            function kdfMemStr(level) {
                if (level < 0 || level >= kdfMemKiB.length) return '—';
                var b = kdfMemKiB[level] * 1024;
                if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
                if (b < 1073741824) return (b/1048576).toFixed(0) + ' MB';
                return (b/1073741824).toFixed(1) + ' GB';
            }
            var sep = slotTbody.insertRow();
            var sepTd = sep.insertCell(0); sepTd.colSpan = 5;
            sepTd.innerHTML = '<b style="color:#4fc3f7">Key Slots</b>';
            sepTd.style.paddingTop = '14px';
            var hdr = slotTbody.insertRow();
            hdr.className = 'slot-hdr';
            ['Slot', 'Level', 'Memory', 'Zone', 'Identifier'].forEach(function(h) {
                var th = hdr.insertCell(); th.textContent = h;
                th.style.cssText = 'color:#aaa;font-size:12px;border-bottom:1px solid #4fc3f7';
                if (h === 'Identifier') th.style.width = 'auto';
                else th.style.width = '1px';
            });
            for (var si = 0; si < slotBlocks.length; si++) {
                var sl = slotBlocks[si];
                var lvl = parseInt((sl.fields.find(function(f) { return f.key === 'Level'; }) || { val: '0' }).val);
                var cells = {
                    'Slot':   { val: String(sl.num) },
                    'Level':  { val: String(isNaN(lvl) ? '-' : lvl) },
                    'Memory': { val: isNaN(lvl) ? '-' : kdfMemStr(lvl) },
                    'Zone':   sl.fields.find(function(f) { return f.key === 'Zone'; }) || { val: '-' },
                    'Identifier': sl.fields.find(function(f) { return f.key === 'Identifier' || f.key === 'Anonymous'; }) || { val: '\u2014' }
                };
                var srow = slotTbody.insertRow();
                ['Slot', 'Level', 'Memory', 'Zone', 'Identifier'].forEach(function(k) {
                    var sc = srow.insertCell(); sc.textContent = cells[k].val;
                    sc.style.borderBottom = '1px solid #1a1a2e';
                });
            }
        }

        statusEl.textContent = 'Remounting...';
        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = '';
    } catch(e) {
        statusEl.textContent = 'Failed: ' + e;
        showError('Metadata Failed', String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}

// ── Tab switching ──────────────────────────────────────────
var _currentTab = '';
function switchTab(name) {
    if (name === _currentTab && document.querySelector('.tab-content[data-tab="' + name + '"]').classList.contains('active')) return;
    _currentTab = name;
    document.querySelectorAll('.sidebar .tab').forEach(function(t) {
        t.classList.toggle('active', t.dataset.tab === name);
    });
    document.querySelectorAll('.content-area .tab-content').forEach(function(c) {
        c.classList.toggle('active', c.dataset.tab === name);
    });
    if (name === 'files') {
        refresh();
    } else if (name === 'aux') {
        loadAux();
    } else if (name === 'meta') {
        loadMeta();
    }
}

document.querySelectorAll('.sidebar .tab').forEach(function(t) {
    t.onclick = function() { switchTab(t.dataset.tab); };
});

// ── Open disk ────────────────────────────────────────────────
async function closeDisk() {
    _shellReady = false; _cwd = '/'; _fsType = ''; _cachedPass = '';
    _fileTree = { dirs: [], files: [] };
    _historyCwd = ['/']; _historyIdx = 0;
    $('#mainApp').style.display = 'none';
    $('#unlockScreen').style.display = 'flex';
    $('#closeBtn').style.display = 'none';
    $('#fileTree').innerHTML = '';
    $('#openBtn').disabled = false;
    if (_worker) { _worker.terminate(); _worker = null; _workerReady = false; }
    location.reload();
}

async function openFile(file) {
    if (!_workerReady) { showError('Worker not ready', 'Worker has not loaded yet.'); return; }
    $('#unlockLoading').style.display = 'flex';
    $('#openBtn').disabled = true;

    _worker.postMessage({ type: 'setup-fs', diskSize: file.size, file: file });
    _cachedPass = $('#passInput').value;

    $('#unlockLoading').textContent = 'Deriving key...';
    _cachedMasterKey = '';
    _worker.postMessage({ type: 'callMain', args: ['Open', '--show-master-key', '--key', _cachedPass, '/disk.img'] });
    _pendingMasterKey = function() {
        _pendingMasterKey = null;
        if (!_cachedMasterKey) {
            showError('Unlock Failed', 'Could not obtain master key.');
            $('#openBtn').disabled = false;
            return;
        }
        $('#unlockLoading').textContent = 'Mounting filesystem...';
        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    };
    setTimeout(function() {
        if (_pendingMasterKey) { _pendingMasterKey = null; showError('Timeout', 'Master key derivation timed out.'); }
    }, 60000);
}

function waitForShell(attempts) {
    if (_shellReady) {
        $('#unlockScreen').style.display = 'none';
        $('#mainApp').style.display = 'flex';
        $('#closeBtn').style.display = 'block';
        $('#roNotice').style.display = 'block';
        _historyCwd = ['/']; _historyIdx = 0;
        updateNavBtns();
        if (!_currentTab) { _currentTab = 'files'; }
        switchTab(_currentTab);
        if (_fsType) $('#fsInfo').textContent = _fsType;
        return;
    }
    if (_lastError && attempts > 10) {
        $('#unlockLoading').textContent = 'Failed.';
        $('#openBtn').disabled = false;
        showError('Unlock Failed', _lastError);
        return;
    }
    if (attempts > 300) {
        $('#unlockLoading').textContent = 'Timeout.';
        $('#openBtn').disabled = false;
        showError('Timeout', 'Unlock took too long.');
        return;
    }
    setTimeout(function() { waitForShell(attempts + 1); }, 100);
}

async function openDisk() {
    if (!_workerReady) { showError('Worker not ready', 'Worker has not loaded yet.'); return; }
    var pass = $('#passInput').value;
    if (!pass) return;

    if (typeof window.showOpenFilePicker === 'function') {
        var handle;
        try {
            [handle] = await window.showOpenFilePicker({
                types: [{description: 'Disk images', accept: {'application/octet-stream': ['.img','.bin','.raw']}}]
            });
        } catch(e) {
            return;
        }
        openFile(await handle.getFile());
    } else {
        $('#fileInput').click();
    }
}

// ── File input / drop-to-open ────────────────────────────────
(function() {
    var fileInput = $('#fileInput');
    fileInput.onchange = function() {
        if (this.files && this.files[0]) openFile(this.files[0]);
        this.value = '';
    };
    var overlay = $('#dropOverlay');
    var dragCounter = 0;
    document.addEventListener('dragenter', function(e) {
        e.preventDefault();
        dragCounter++;
        if (!_shellReady) overlay.classList.add('active');
    });
    document.addEventListener('dragleave', function(e) {
        e.preventDefault();
        dragCounter--;
        if (dragCounter <= 0) { dragCounter = 0; overlay.classList.remove('active'); }
    });
    document.addEventListener('dragover', function(e) { e.preventDefault(); });
    document.addEventListener('drop', function(e) {
        e.preventDefault();
        dragCounter = 0;
        overlay.classList.remove('active');
        if (!_shellReady && e.dataTransfer.files && e.dataTransfer.files[0])
            openFile(e.dataTransfer.files[0]);
    });
})();

// ── Events ─────────────────────────────────────────────────────
$('#passInput').oninput   = function() { $('#openBtn').disabled = !this.value; };
$('#passInput').onkeydown = function(e) { if (e.key === 'Enter') openDisk(); };
$('#openBtn').onclick     = openDisk;
$('#navBack').onclick     = navBack;
$('#navFwd').onclick      = navFwd;
$('#refreshBtn').onclick  = refresh;
$('#closeBtn').onclick    = closeDisk;
