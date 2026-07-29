// Windham Web Worker — Emscripten WASM + ASYNCIFY, streaming I/O

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

self.addEventListener('message', function(e) {
    var d = e.data;
    switch (d.type) {
    case 'setup-fs':
        _diskFile = d.file;
        _diskSize = d.diskSize;
        Module.FS.writeFile('/disk_size', String(d.diskSize));

        var reader = new FileReaderSync();
        var ab = reader.readAsArrayBuffer(_diskFile);
        Module.FS.writeFile('/disk.img', new Uint8Array(ab));

        Module.FS.writeFile('/cmd_queue', new Uint8Array(0));
        try { Module.FS.mkdir('/tmp'); } catch(ex) {}
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
