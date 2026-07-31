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
    printErr: function(t){ self.postMessage({ type: 'stderr', text: t }); },
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
    },
    llseek: function(stream, offset, whence) {
        var newPos;
        if (whence === 0) newPos = offset;
        else if (whence === 1) newPos = stream.position + offset;
        else if (whence === 2) newPos = _diskSize + offset;
        else return -1;
        if (newPos < 0) return -1;
        stream.position = newPos;
        return newPos;
    },
    allocate: function(stream, offset, length) {
        if (offset + length > stream.node.usedBytes)
            stream.node.usedBytes = offset + length;
        return 0;
    }
};

function setupDiskImage(file, size) {
    _diskFile = file;
    _diskSize = size;

    Module.FS.writeFile('/disk_size', String(size));
    Module.FS.writeFile('/cmd_queue', new Uint8Array(0));
    try { Module.FS.mkdir('/tmp'); } catch(ex) {}

    try { Module.FS.unlink('/disk.img'); } catch(e) {}

    Module.FS.createDataFile('/', 'disk.img', new Uint8Array(0), true, true, true);
    var node = Module.FS.lookupPath('/disk.img').node;
    node.usedBytes = size;
    node.stream_ops = _diskStreamOps;
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
