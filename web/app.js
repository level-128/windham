// Windham Web — sidebar-driven disk browser
// ── i18n ───────────────────────────────────────────────────
_lang = detectLang();
setLang(_lang);
var _langSelect = document.getElementById('langSelect');
_langSelect.value = _lang;
_langSelect.onchange = function() { setLang(this.value); };

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
var _pendingChunk = null;
var _transferBusy = false;
var _previewURL = null;
var _previewName = '';
var _previewSize = 0;

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
        showError(t('Browser not supported'),
            t('Your browser is missing required APIs') + ':\n\u2022 ' +
            _browserIssues.join('\n\u2022 ') + '\n\n' +
            t('Use Chrome 86+ or Edge 86+ for full support.'));
        return;
    }
    _worker = new Worker('worker.js?v=6');
    _worker.onerror = function(e) {
        showError(t('Worker Crashed'), e.message || t('Unknown error'));
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
            showError(t('Worker Error'), d.msg);
            break;
        case 'stdout':
            handleStdout(d.text);
            break;
        case 'stderr':
            _lastError = d.text;
            if (_pendingCmd) { _pendingCmd.reject(d.text); _pendingCmd = null; }
            break;
        case 'chunk-data':
            if (_pendingChunk && _pendingChunk.path === d.path && _pendingChunk.offset === d.offset) {
                var ck = _pendingChunk; _pendingChunk = null;
                ck.resolve(d.data);
            }
            break;
        case 'file-error':
            if (_pendingChunk && _pendingChunk.path === d.path) {
                var ce = _pendingChunk; _pendingChunk = null;
                ce.reject(new Error(d.msg));
            }
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
    // Capture master key: hex bytes separated by spaces
    if (_pendingMasterKey && /^[0-9a-f]{2}( [0-9a-f]{2})+/.test(text.trim())) {
        _cachedMasterKey = text.replace(/\s/g, '');
        _pendingMasterKey(); _pendingMasterKey = null;
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
    $('#fileCount').textContent = tf('%d dirs, %d files', _fileTree.dirs.length, _fileTree.files.length);
}

function makeItem(icon, name, size, cls, onclick) {
    var d = document.createElement('div');
    d.className = 'tree-item ' + cls;
    d.innerHTML = '<span class="icon">' + icon + '</span><span class="name">' + esc(name) + '</span><span class="size">' + (size > 0 ? fmtSize(size) : '') + '</span><span class="dl" title="Download">⬇</span>';
    d.onclick = onclick;
    var dl = d.querySelector('.dl');
    if (dl && cls !== 'dir') dl.onclick = function(e) { e.stopPropagation(); exportFile(name, size); };
    return d;
}

async function cd(dir) {
    await shellCmd(dir === '..' ? 'cd ..' : 'cd ' + dir);
    if (_lastError) { showError(t('cd Failed'), _lastError); return; }
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
    if (_lastError) { showError(t('ls Failed'), _lastError); return; }
    _fileTree = parseLs(output);
    renderTree();
}

// ── File transfer: export / download / preview ───────────────
var CHUNK_SIZE = 1048576;   // 1 MiB per read-chunk round trip
var TEXT_HEAD  = 262144;    // bytes fetched for text preview
var HEX_HEAD   = 4096;      // bytes shown in the hex view
var PREVIEW_CAPS = { image: 64*1048576, pdf: 128*1048576,
                     audio: 512*1048576, video: 512*1048576, unknown: 64*1048576 };

var EXT_KINDS = {
    text: ('txt md log csv json xml html htm css js ts c h cpp hpp cc cxx py pyw sh bash zsh fish ps1 bat ' +
           'ini cfg conf config toml yaml yml rst tex srt ass patch diff go rs java kt kts php rb sql pl lua vim ' +
           'emacs service automount desktop list m3u m3u8 nfo gitignore dockerfile makefile cmakelists').split(' '),
    image: 'png jpg jpeg gif webp bmp svg ico avif jfif'.split(' '),
    pdf: 'pdf'.split(' '),
    audio: 'mp3 wav ogg oga flac m4a aac opus wma mid'.split(' '),
    video: 'mp4 webm mkv mov m4v avi wmv ts'.split(' ')
};
var EXT_MIME = {
    png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp',
    bmp:'image/bmp', svg:'image/svg+xml', ico:'image/x-icon', avif:'image/avif', jfif:'image/jpeg',
    pdf:'application/pdf',
    mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg', oga:'audio/ogg', flac:'audio/flac',
    m4a:'audio/mp4', aac:'audio/aac', opus:'audio/ogg', wma:'audio/x-ms-wma',
    mp4:'video/mp4', webm:'video/webm', mkv:'video/x-matroska', mov:'video/quicktime',
    m4v:'video/mp4', avi:'video/x-msvideo', wmv:'video/x-ms-wmv', ts:'video/mp2t'
};

function extOf(name) {
    var i = name.lastIndexOf('.');
    return i < 0 ? '' : name.substring(i + 1).toLowerCase();
}
function classifyByName(name) {
    var ext = extOf(name);
    for (var k in EXT_KINDS)
        if (EXT_KINDS[k].indexOf(ext) >= 0) return k;
    return 'unknown';
}

// content sniffing for extensionless / unknown files
function sniffKind(b) {
    if (!b || !b.length) return 'text';
    function magic(s, off) {
        off = off || 0;
        for (var i = 0; i < s.length; i++) if (b[off + i] !== s.charCodeAt(i)) return false;
        return true;
    }
    if (magic('\x89PNG')) return 'image/png';
    if (magic('\xff\xd8\xff')) return 'image/jpeg';
    if (magic('GIF8')) return 'image/gif';
    if (magic('BM')) return 'image/bmp';
    if (magic('RIFF') && magic('WEBP', 8)) return 'image/webp';
    if (magic('%PDF')) return 'pdf';
    var n = Math.min(b.length, 4096), ctrl = 0;
    for (var i = 0; i < n; i++) {
        var c = b[i];
        if (c === 0) return 'binary';
        if (c < 9 || (c > 13 && c < 32)) ctrl++;
    }
    return ctrl * 32 < n ? 'text' : 'binary';
}

function decodeTextBytes(bytes) {
    if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE)
        return new TextDecoder('utf-16le').decode(bytes.subarray(2));
    if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF)
        return new TextDecoder('utf-16be').decode(bytes.subarray(2));
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF)
        return new TextDecoder('utf-8').decode(bytes.subarray(3));
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (e) {
        try { return new TextDecoder('windows-1252').decode(bytes); }
        catch (e2) { return new TextDecoder('utf-8').decode(bytes); }
    }
}

function requestFileChunk(path, offset, length) {
    return new Promise(function(resolve, reject) {
        _pendingChunk = { path: path, offset: offset, resolve: resolve, reject: reject };
        _worker.postMessage({ type: 'read-chunk', path: path, offset: offset, length: length });
    });
}

async function exportToTemp(fpath, tempPath, head) {
    _worker.postMessage({ type: 'unlink', path: tempPath });
    _lastError = '';
    try {
        await shellCmd('export ' + (head ? '--head ' + head + ' ' : '') + fpath + ' ' + tempPath);
    } catch (e) {
        throw new Error(_lastError || String(e));
    }
}

function fatPathOf(name) {
    return (_cwd === '/' ? '' : _cwd) + '/' + name;
}

// ── Preview panel helpers ─────────────────────────────────────
function openPreviewPanel(name, size) {
    _previewName = name; _previewSize = size;
    $('#previewName').textContent = name;
    $('#previewSize').textContent = size > 0 ? fmtSize(size) : '';
    $('#previewPanel').style.display = 'flex';
    $('#previewDl').style.display = size > 0 ? 'inline' : 'none';
}
function setPreviewStatus(text) {
    var el = $('#previewBody');
    el.className = 'preview-body';
    el.textContent = text;
}
function setPreviewProgress(got, total) {
    var el = $('#previewBody');
    el.className = 'preview-body';
    el.textContent = t('Downloading...') + ' ' + fmtSize(got) +
                     (total > 0 ? ' / ' + fmtSize(total) : '');
}
function clearPreviewMedia() {
    if (_previewURL) { URL.revokeObjectURL(_previewURL); _previewURL = null; }
}

function renderTextPreview(bytes, size) {
    var el = $('#previewBody');
    el.className = 'preview-body';
    el.innerHTML = '';
    var pre = document.createElement('pre');
    pre.textContent = decodeTextBytes(bytes);
    el.appendChild(pre);
    if (bytes.length < size) {
        var note = document.createElement('div');
        note.className = 'truncated';
        note.textContent = tf('Showing first %s of the file.', fmtSize(bytes.length));
        el.appendChild(note);
    }
}

function renderHexPreview(bytes, size) {
    var lines = [];
    for (var off = 0; off < bytes.length; off += 16) {
        var hex = '', asc = '';
        for (var i = 0; i < 16; i++) {
            var has = off + i < bytes.length;
            var b = has ? bytes[off + i] : 0;
            hex += (has ? ((b < 16 ? '0' : '') + b.toString(16)) : '  ') + ' ';
            asc += has ? ((b >= 32 && b < 127) ? String.fromCharCode(b) : '.') : ' ';
        }
        lines.push(('00000000' + off.toString(16)).slice(-8) + '  ' + hex + ' ' + asc);
    }
    var el = $('#previewBody');
    el.className = 'preview-body';
    el.innerHTML = '';
    var pre = document.createElement('pre');
    pre.textContent = lines.join('\n');
    el.appendChild(pre);
    if (bytes.length < size) {
        var note = document.createElement('div');
        note.className = 'truncated';
        note.textContent = tf('Showing first %s of the file.', fmtSize(bytes.length));
        el.appendChild(note);
    }
}

function renderMediaPreview(kind, mime, blob) {
    clearPreviewMedia();
    _previewURL = URL.createObjectURL(blob);
    var el = $('#previewBody');
    el.innerHTML = '';
    var node;
    if (kind === 'image') {
        node = document.createElement('img');
        node.alt = _previewName;
    } else if (kind === 'pdf') {
        node = document.createElement('iframe');
        node.title = _previewName;
        el.className = 'preview-body media-fill';
    } else if (kind === 'audio') {
        node = document.createElement('audio');
        node.controls = true;
    } else {
        node = document.createElement('video');
        node.controls = true;
    }
    node.src = _previewURL;
    el.appendChild(node);
}

// ── Preview (click on file) ───────────────────────────────────
async function previewFile(name, size) {
    if (_transferBusy) return;
    _transferBusy = true;
    var fpath = fatPathOf(name);
    openPreviewPanel(name, size);
    setPreviewStatus(size === 0 ? t('File is empty.') : t('Loading preview...'));
    try {
        var kind = classifyByName(name);
        var head = null;

        if (kind === 'unknown' || kind === 'text') {
            // cheap head export: enough for text render and content sniffing
            await exportToTemp(fpath, '/tmp/.pv', TEXT_HEAD);
            head = await requestFileChunk('/tmp/.pv', 0, TEXT_HEAD);
            if (kind === 'unknown') {
                var sniff = sniffKind(head);
                if (sniff === 'text') kind = 'text';
                else if (sniff === 'binary') kind = 'hex';
                else if (sniff === 'pdf') kind = 'pdf';
                else kind = { mime: sniff };   // sniffed image/*
            }
        }

        if (kind === 'text') {
            renderTextPreview(head, size);
        } else if (kind === 'hex') {
            renderHexPreview(head.subarray(0, HEX_HEAD), size);
        } else {
            var isImg = typeof kind === 'object';
            var k = isImg ? 'image' : kind;
            var cap = PREVIEW_CAPS[k] || PREVIEW_CAPS.unknown;
            if (size > cap) {
                setPreviewStatus(tf('File too large to preview (max %s).', fmtSize(cap)));
                return;
            }
            if (size === 0) return;
            await exportToTemp(fpath, '/tmp/.pv', 0);
            var mime = isImg ? kind.mime : (EXT_MIME[extOf(name)] || 'application/octet-stream');
            var chunks = [];
            var got = 0;
            for (;;) {
                var data = await requestFileChunk('/tmp/.pv', got, CHUNK_SIZE);
                if (!data || data.length === 0) break;
                chunks.push(data);
                got += data.length;
                setPreviewProgress(got, size);
                if (data.length < CHUNK_SIZE) break;
            }
            renderMediaPreview(k, mime, new Blob(chunks, { type: mime }));
        }
    } catch (e) {
        setPreviewStatus(tf('Failed: %s', e));
    } finally {
        _worker.postMessage({ type: 'unlink', path: '/tmp/.pv' });
        _transferBusy = false;
    }
}

// ── Download (⬇ button) ───────────────────────────────────────
async function downloadFile(name, size) {
    if (_transferBusy) return;
    _transferBusy = true;
    var fpath = fatPathOf(name);
    // grab the save handle first: user activation expires after awaits
    var writable = null;
    if (typeof window.showSaveFilePicker === 'function') {
        try {
            var handle = await window.showSaveFilePicker({ suggestedName: name });
            writable = await handle.createWritable();
        } catch (e) {
            if (e && e.name === 'AbortError') { _transferBusy = false; return; }
            writable = null;   // fall back to in-memory Blob download
        }
    }
    openPreviewPanel(name, size);
    try {
        await exportToTemp(fpath, '/tmp/.dl', 0);
        var got = 0;
        if (writable) {
            // stream chunk-by-chunk straight to disk - constant memory
            for (;;) {
                var data = await requestFileChunk('/tmp/.dl', got, CHUNK_SIZE);
                if (!data || data.length === 0) break;
                await writable.write(data);
                got += data.length;
                setPreviewProgress(got, size);
                if (data.length < CHUNK_SIZE) break;
            }
            await writable.close();
            writable = null;
        } else {
            var chunks = [];
            for (;;) {
                var data2 = await requestFileChunk('/tmp/.dl', got, CHUNK_SIZE);
                if (!data2 || data2.length === 0) break;
                chunks.push(data2);
                got += data2.length;
                setPreviewProgress(got, size);
                if (data2.length < CHUNK_SIZE) break;
            }
            var link = document.createElement('a');
            link.download = name;
            link.href = URL.createObjectURL(new Blob(chunks));
            link.click();
            setTimeout(function() { URL.revokeObjectURL(link.href); }, 60000);
        }
    } catch (e) {
        showError(t('Export Failed'), String(e));
        if (writable) { try { writable.close(); } catch (e2) {} }
    } finally {
        _worker.postMessage({ type: 'unlink', path: '/tmp/.dl' });
        _transferBusy = false;
    }
}

async function exportFile(name, size) { await downloadFile(name, size); }

function closePreview() {
    clearPreviewMedia();
    $('#previewPanel').style.display = 'none';
}
$('#previewClose').onclick = closePreview;
$('#previewDl').onclick = function() { if (_previewName) downloadFile(_previewName, _previewSize); };

// ── Backup tab ──────────────────────────────────────────────
async function backupFold() {
    var statusEl = $('#buStatus');
    if (!_cachedPass) { statusEl.textContent = t('No passphrase available. Re-open the disk first.'); return; }
    try {
        statusEl.textContent = t('Exiting shell...');
        _shellExited = false;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');

        statusEl.textContent = t('Creating fold backup...');
        var backupDone = new Promise(function(r) { _pendingBackupDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Backup', '--fold', '--to', '/tmp/fold.bu', '--key', _cachedPass, '/disk.img'] });
        await Promise.race([backupDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('backup timeout')); }, 30000); })]);

        statusEl.textContent = t('Reading backup...');
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
        statusEl.textContent = t('Backup downloaded. Remounting...');

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = t('Backup complete.');
    } catch(e) {
        statusEl.textContent = tf('Backup failed: %s', e);
        showError(t('Backup Failed'), String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}

$('#buDownloadBtn').onclick = backupFold;

async function showQr() {
    var statusEl = $('#buStatus');
    var canvasEl = $('#qrCanvas');
    if (!_cachedPass) { statusEl.textContent = t('No passphrase available.'); return; }
    try {
        statusEl.textContent = t('Exiting shell...');
        _shellExited = false;
        var exitPromise = new Promise(function(r) { _pendingShellExit = r; });
        await shellCmd('exit');
        await Promise.race([exitPromise, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('exit timeout')); }, 10000); })]);
        if (!_shellExited) throw new Error('Shell did not exit');

        statusEl.textContent = t('Generating QR code...');
        _stdoutAcc = '';
        var backupDone = new Promise(function(r) { _pendingBackupDone = r; });
        _worker.postMessage({ type: 'callMain', args: ['Backup', '--qrcode=/tmp/qr.bmp', '--to', '/tmp/fold.bu', '--key', _cachedPass, '/disk.img'] });
        await Promise.race([backupDone, new Promise(function(_, rej) { setTimeout(function() { rej(new Error('timeout')); }, 30000); })]);

        statusEl.textContent = t('Reading QR image...');
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
        statusEl.textContent = t('QR code generated.');

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    } catch(e) {
        statusEl.textContent = tf('QR failed: %s', e);
        showError(t('QR Failed'), String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}
$('#buQrBtn').onclick = showQr;

// ── Aux tab ──────────────────────────────────────────────────
async function loadAux() {
    var statusEl = $('#auxStatus');
    var outputEl = $('#auxOutput');
    outputEl.textContent = t('Loading...');
    if (!_cachedPass) { outputEl.textContent = t('No passphrase available.'); return; }
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
        outputEl.textContent = filtered.join('\n').trim() || t('No aux entries found.');

        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = '';
    } catch(e) {
        outputEl.textContent = tf('Failed: %s', e);
        showError(t('Aux Failed'), String(e));
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    }
}

// ── Metadata tab ────────────────────────────────────────────
async function loadMeta() {
    var statusEl = $('#metaStatus');
    if (!_cachedMasterKey) { statusEl.textContent = t('No master key available.'); return; }
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
                var th = hdr.insertCell(); th.textContent = t(h);
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

        statusEl.textContent = t('Remounting...');
        _shellExited = false;
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
        statusEl.textContent = '';
    } catch(e) {
        statusEl.textContent = tf('Failed: %s', e);
        showError(t('Metadata Failed'), String(e));
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
    clearPreviewMedia();
    $('#mainApp').style.display = 'none';
    $('#unlockScreen').style.display = 'flex';
    $('#closeBtn').style.display = 'none';
    $('#fileTree').innerHTML = '';
    $('#openBtn').disabled = false;
    if (_worker) { _worker.terminate(); _worker = null; _workerReady = false; }
    location.reload();
}

async function openFile(file) {
    if (!_workerReady) { showError(t('Worker not ready'), t('Worker has not loaded yet.')); return; }
    $('#unlockLoading').style.display = 'flex';
    $('#openBtn').disabled = true;

    _worker.postMessage({ type: 'setup-fs', diskSize: file.size, file: file });
    _cachedPass = $('#passInput').value;

    $('#unlockLoading').textContent = t('Deriving key...');
    _cachedMasterKey = '';
    _worker.postMessage({ type: 'callMain', args: ['Open', '--show-master-key', '--key', _cachedPass, '/disk.img'] });
    _pendingMasterKey = function() {
        _pendingMasterKey = null;
        if (!_cachedMasterKey) {
            showError(t('Unlock Failed'), t('Could not obtain master key.'));
            $('#openBtn').disabled = false;
            return;
        }
        $('#unlockLoading').textContent = t('Mounting filesystem...');
        _shellExited = false;
        _lastError = '';   // main #1's normal exit() may have left a stale message
        _worker.postMessage({ type: 'callMain', args: ['Open', '--key', _cachedPass, '/disk.img'] });
        waitForShell(0);
    };
    setTimeout(function() {
        if (_pendingMasterKey) { _pendingMasterKey = null; showError(t('Timeout'), t('Master key derivation timed out.')); }
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
        // Leave _currentTab empty on first unlock: switchTab's same-tab guard
        // (files is marked active in the initial HTML) would otherwise skip
        // the initial refresh() and leave the file tree blank.
        switchTab(_currentTab || 'files');
        if (_fsType) $('#fsInfo').textContent = _fsType;
        return;
    }
    if (_lastError && attempts > 10) {
        $('#unlockLoading').textContent = t('Failed.');
        $('#openBtn').disabled = false;
        showError(t('Unlock Failed'), _lastError);
        return;
    }
    if (attempts > 300) {
        $('#unlockLoading').textContent = t('Timeout.');
        $('#openBtn').disabled = false;
        showError(t('Timeout'), t('Unlock took too long.'));
        return;
    }
    setTimeout(function() { waitForShell(attempts + 1); }, 100);
}

async function openDisk() {
    if (!_workerReady) { showError(t('Worker not ready'), t('Worker has not loaded yet.')); return; }
    var pass = $('#passInput').value;
    if (!pass) return;

    if (typeof window.showOpenFilePicker === 'function') {
        var handle;
        try {
            [handle] = await window.showOpenFilePicker({
                types: [{description: t('Disk images'), accept: {'application/octet-stream': ['.img','.bin','.raw']}}]
            });
        } catch(e) {
            return;
        }
        var file = await handle.getFile();
        openFile(file);
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
        if (_shellReady) return;
        var file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        openFile(file);
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
