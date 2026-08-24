// Windham Web Worker — Emscripten WASM + ASYNCIFY, partial reads via File.slice()

var stdinWake = new Int32Array(new SharedArrayBuffer(4));
var stdinChars = '';
Atomics.store(stdinWake, 0, 0);

var _diskFile = null;
var _diskSize = 0;

var Module = {
    noInitialRun: true,
    noExitRuntime: true,
    onRuntimeInitialized: function() {
        console.log('[worker] WASM ready');
        self.postMessage({ type: 'loaded' });
    },
    print: function(t)   { self.postMessage({ type: 'stdout', text: t }); },
    printErr: function(t){
        // Emscripten prints "program exited (with status: N), but keepRuntimeAlive() is set
        // (counter=0)..." to stderr on a normal exit() while async work is pending. It is
        // informational noise, not a real error - swallowing it keeps _lastError clean.
        if (typeof t === 'string' && t.indexOf('keepRuntimeAlive() is set') >= 0) return;
        self.postMessage({ type: 'stderr', text: t });
    },
    stdin: function() {
        if (stdinChars.length) { var c = stdinChars.charCodeAt(0); stdinChars = stdinChars.slice(1); return c; }
        do { Atomics.wait(stdinWake, 0, 0); } while (!stdinChars.length);
        var c = stdinChars.charCodeAt(0); stdinChars = stdinChars.slice(1); return c;
    }
};

try { importScripts('windham.js'); } catch(e) {
    self.postMessage({ type: 'error', msg: 'importScripts: ' + e });
}

function readChunk(offset, length) {
    var blob = _diskFile.slice(offset, Math.min(offset + length, _diskSize));
    return new Uint8Array(new FileReaderSync().readAsArrayBuffer(blob));
}

// FS.lookupPath was removed in newer Emscripten; a stream always exposes its
// node though ("node" is part of the public stream-ops calling convention).
function fsNode(path) {
    var stream = Module.FS.open(path, 'r');
    var node = stream.node;
    Module.FS.close(stream);
    return node;
}

// Newer Emscripten minifies node internals (stream_ops -> "i"), so locate the
// stream-ops property by shape: an object holding both read and write fns.
function findStreamOpsKey(node) {
    var keys = Object.keys(node);
    for (var i = 0; i < keys.length; i++) {
        var v = node[keys[i]];
        if (v && typeof v === 'object' && typeof v.read === 'function' && typeof v.write === 'function')
            return keys[i];
    }
    return null;
}

// MEMFS keeps the file size in node.usedBytes ("o" when minified). Locate the
// property by probing a throwaway file with a distinctive length.
function setNodeFileSize(node, size) {
    var PROBE_SIZE = 4919;
    try {
        Module.FS.writeFile('/.size_probe', new Uint8Array(PROBE_SIZE));
        var pnode = fsNode('/.size_probe');
        var keys = Object.keys(pnode);
        for (var i = 0; i < keys.length; i++) {
            if (pnode[keys[i]] === PROBE_SIZE) { node[keys[i]] = size; break; }
        }
        Module.FS.unlink('/.size_probe');
    } catch (e) {
        if ('usedBytes' in node) node.usedBytes = size;
    }
}

var _diskStreamOps = {
    open: function(stream) { return 0; },
    close: function(stream) {},
    read: function(stream, buffer, offset, length, position) {
        if (position == null) position = stream.position;
        if (position >= _diskSize || length <= 0) return 0;
        if (position + length > _diskSize) length = _diskSize - position;
        var chunk = readChunk(position, length);
        buffer.set(chunk, offset);
        return chunk.byteLength;
    },
    write: function(stream, buffer, offset, length, position) {
        return 0;
    }
};

function setupDiskImage(file, size) {
    _diskFile = file;
    _diskSize = size;

    if (!Module.FS || typeof Module.FS.writeFile !== 'function') {
        self.postMessage({ type: 'error', msg: 'WASM filesystem not ready yet.' });
        return;
    }

    Module.FS.writeFile('/disk_size', String(size));
    Module.FS.writeFile('/cmd_queue', new Uint8Array(0));
    try { Module.FS.mkdir('/tmp'); } catch(ex) {}

    try { Module.FS.unlink('/disk.img'); } catch(e) {}

    // Create an empty /disk.img and swap in custom stream ops that serve
    // reads from the browser File via slice()+FileReaderSync. Build the ops
    // on top of the node's default ops so llseek/mmap/allocate keep working
    // under their (possibly minified) names.
    Module.FS.writeFile('/disk.img', new Uint8Array(0));
    var node = fsNode('/disk.img');
    if (!node || !node.mode) {
        self.postMessage({ type: 'error', msg: 'Cannot access /disk.img node.' });
        return;
    }
    var opsKey = findStreamOpsKey(node);
    if (opsKey) {
        var ops = {};
        for (var k in node[opsKey]) ops[k] = node[opsKey][k];
        ops.open  = _diskStreamOps.open;
        ops.close = _diskStreamOps.close;
        ops.read  = _diskStreamOps.read;
        ops.write = _diskStreamOps.write;
        node[opsKey] = ops;
    } else {
        node.stream_ops = _diskStreamOps;
    }
    setNodeFileSize(node, size);
}

self.addEventListener('message', function(e) {
    var d = e.data;
    switch (d.type) {
    case 'setup-fs':
        setupDiskImage(d.file, d.diskSize);
        self.postMessage({ type: 'ready' });
        break;
    case 'callMain':
        Module['calledRun'] = false;
        var args = ['windham'].concat(d.args);
        var argc = args.length, argv = Module._malloc((argc+1)*4);
        var dv = new DataView(Module.HEAPU8.buffer);
        for (var i = 0; i < argc; i++) {
            var len = Module.lengthBytesUTF8(args[i]) + 1;
            var p = Module._malloc(len);
            Module.stringToUTF8(args[i], p, len);
            dv.setUint32(argv + i*4, p, true);
        }
        dv.setUint32(argv + argc*4, 0, true);
        try {
            Module._main(argc, argv);
        } catch(e) {
            if (e && e.name === 'ExitStatus') { /* normal exit */ }
            else { self.postMessage({ type: 'error', msg: 'main: ' + e }); }
        }
        break;
    case 'read-file':
        try {
            var data = Module.FS.readFile(d.path, { encoding: 'binary' });
            self.postMessage({ type: 'file-data', path: d.path, data: data }, [data.buffer]);
        } catch(e) {
            self.postMessage({ type: 'file-error', path: d.path, msg: String(e) });
        }
        break;
    case 'read-chunk':
        // positional read (pread): serves export/preview without holding the
        // whole file in a JS-side buffer
        try {
            var stream = Module.FS.open(d.path, 'r');
            var buf = new Uint8Array(d.length);
            var n = Module.FS.read(stream, buf, 0, d.length, d.offset);
            Module.FS.close(stream);
            if (n < d.length) buf = buf.subarray(0, n);
            self.postMessage({ type: 'chunk-data', path: d.path, offset: d.offset,
                               data: buf, bytes: n }, [buf.buffer]);
        } catch(e) {
            self.postMessage({ type: 'file-error', path: d.path, msg: String(e) });
        }
        break;
    case 'unlink':
        try { Module.FS.unlink(d.path); } catch(e) {}
        break;
    case 'cmd-queue':
        Module.FS.writeFile('/cmd_queue', d.text);
        break;
    case 'stdin':
        stdinChars += d.text;
        Atomics.store(stdinWake, 0, 1);
        Atomics.notify(stdinWake, 0, 1);
        break;
    }
});
