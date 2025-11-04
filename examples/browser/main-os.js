var Module = (() => {
  return (async function (moduleArg = {}) {
    var moduleRtn;
    var Module = moduleArg;
    var readyPromiseResolve, readyPromiseReject;
    var readyPromise = new Promise((resolve, reject) => {
      readyPromiseResolve = resolve;
      readyPromiseReject = reject
    });
    var ENVIRONMENT_IS_WEB = typeof window == "object";
    var ENVIRONMENT_IS_WORKER = typeof WorkerGlobalScope != "undefined";
    var ENVIRONMENT_IS_NODE = typeof process == "object" && process.versions?.node && process.type != "renderer";
    // var ENVIRONMENT_IS_PTHREAD = ENVIRONMENT_IS_WORKER && self.name?.startsWith("em-pthread");
    var arguments_ = [];
    var thisProgram = "./this.program";
    var quit_ = (status, toThrow) => {
      throw toThrow
    };
    var _scriptName = import.meta.url;
    var scriptDirectory = "";

    function locateFile(path) {
      if (Module["locateFile"]) {
        return Module["locateFile"](path, scriptDirectory)
      }
      return scriptDirectory + path
    }
    var readAsync, readBinary;
    if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
      try {
        scriptDirectory = new URL(".", _scriptName).href
      } catch { } {
        if (ENVIRONMENT_IS_WORKER) {
          readBinary = url => {
            var xhr = new XMLHttpRequest;
            xhr.open("GET", url, false);
            xhr.responseType = "arraybuffer";
            xhr.send(null);
            return new Uint8Array(xhr.response)
          }
        }
        readAsync = async url => {
          var response = await fetch(url, {
            credentials: "same-origin"
          });
          if (response.ok) {
            return response.arrayBuffer()
          }
          throw new Error(response.status + " : " + response.url)
        }
      }
    } else { }
    var out = console.log.bind(console);
    var err = console.error.bind(console);
    var wasmBinary;
    var wasmMemory;
    var wasmModule;
    var ABORT = false;
    var EXITSTATUS;
    var HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAP64, HEAPU64, HEAPF64;
    var runtimeInitialized = false;

    function growMemViews() {
      if (wasmMemory.buffer != HEAP8.buffer) {
        updateMemoryViews()
      }
    }
    // var wasmModuleReceived;
    // if (ENVIRONMENT_IS_PTHREAD) {
    //   var initializedJS = false;
    //   self.onunhandledrejection = e => {
    //     throw e.reason || e
    //   };

    //   function handleMessage(e) {
    //     try {
    //       var msgData = e["data"];
    //       var cmd = msgData.cmd;
    //       if (cmd === "load") {
    //         let messageQueue = [];
    //         self.onmessage = e => messageQueue.push(e);
    //         self.startWorker = instance => {
    //           postMessage({
    //             cmd: "loaded"
    //           });
    //           for (let msg of messageQueue) {
    //             handleMessage(msg)
    //           }
    //           self.onmessage = handleMessage
    //         };
    //         for (const handler of msgData.handlers) {
    //           if (!Module[handler] || Module[handler].proxy) {
    //             Module[handler] = (...args) => {
    //               postMessage({
    //                 cmd: "callHandler",
    //                 handler,
    //                 args
    //               })
    //             };
    //             if (handler == "print") out = Module[handler];
    //             if (handler == "printErr") err = Module[handler]
    //           }
    //         }
    //         wasmMemory = msgData.wasmMemory;
    //         updateMemoryViews();
    //         wasmModuleReceived(msgData.wasmModule)
    //       } else if (cmd === "run") {
    //         establishStackSpace(msgData.pthread_ptr);
    //         __emscripten_thread_init(msgData.pthread_ptr, 0, 0, 1, 0, 0);
    //         PThread.threadInitTLS();
    //         __emscripten_thread_mailbox_await(msgData.pthread_ptr);
    //         if (!initializedJS) {
    //           initializedJS = true
    //         }
    //         try {
    //           invokeEntryPoint(msgData.start_routine, msgData.arg)
    //         } catch (ex) {
    //           if (ex != "unwind") {
    //             throw ex
    //           }
    //         }
    //       } else if (msgData.target === "setimmediate") { } else if (cmd === "checkMailbox") {
    //         if (initializedJS) {
    //           checkMailbox()
    //         }
    //       } else if (cmd) {
    //         err(`worker: received unknown command ${cmd}`);
    //         err(msgData)
    //       }
    //     } catch (ex) {
    //       __emscripten_thread_crashed();
    //       throw ex
    //     }
    //   }
    //   self.onmessage = handleMessage
    // }

    function updateMemoryViews() {
      var b = wasmMemory.buffer;
      HEAP8 = new Int8Array(b);
      HEAP16 = new Int16Array(b);
      HEAPU8 = new Uint8Array(b);
      HEAPU16 = new Uint16Array(b);
      HEAP32 = new Int32Array(b);
      HEAPU32 = new Uint32Array(b);
      HEAPF32 = new Float32Array(b);
      HEAPF64 = new Float64Array(b);
      HEAP64 = new BigInt64Array(b);
      HEAPU64 = new BigUint64Array(b)
    }

    function initMemory() {
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   return
      // }
      if (Module["wasmMemory"]) {
        wasmMemory = Module["wasmMemory"]
      } else {
        var INITIAL_MEMORY = Module["INITIAL_MEMORY"] || 16777216;
        wasmMemory = new WebAssembly.Memory({
          initial: INITIAL_MEMORY / 65536,
          maximum: 32768,
          shared: true
        })
      }
      updateMemoryViews()
    }

    function preRun() {
      if (Module["preRun"]) {
        if (typeof Module["preRun"] == "function") Module["preRun"] = [Module["preRun"]];
        while (Module["preRun"].length) {
          addOnPreRun(Module["preRun"].shift())
        }
      }
      callRuntimeCallbacks(onPreRuns)
    }

    function initRuntime() {
      runtimeInitialized = true;
      // if (ENVIRONMENT_IS_PTHREAD) return startWorker(Module);
      if (!Module["noFSInit"] && !FS.initialized) FS.init();
      TTY.init();
      PTY.onSignal(signalName => {
        let signalCode = PTY_signalNameToCode[signalName];
        _raise(signalCode)
      });
      wasmExports["_"]();
      FS.ignorePermissions = false
    }

    function preMain() { }

    function postRun() {
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   return
      // }
      if (Module["postRun"]) {
        if (typeof Module["postRun"] == "function") Module["postRun"] = [Module["postRun"]];
        while (Module["postRun"].length) {
          addOnPostRun(Module["postRun"].shift())
        }
      }
      callRuntimeCallbacks(onPostRuns)
    }
    var runDependencies = 0;
    var dependenciesFulfilled = null;

    function getUniqueRunDependency(id) {
      return id
    }

    function addRunDependency(id) {
      runDependencies++;
      Module["monitorRunDependencies"]?.(runDependencies)
    }

    function removeRunDependency(id) {
      runDependencies--;
      Module["monitorRunDependencies"]?.(runDependencies);
      if (runDependencies == 0) {
        if (dependenciesFulfilled) {
          var callback = dependenciesFulfilled;
          dependenciesFulfilled = null;
          callback()
        }
      }
    }

    function abort(what) {
      Module["onAbort"]?.(what);
      what = "Aborted(" + what + ")";
      err(what);
      ABORT = true;
      what += ". Build with -sASSERTIONS for more info.";
      var e = new WebAssembly.RuntimeError(what);
      readyPromiseReject(e);
      throw e
    }
    var wasmBinaryFile;

    function findWasmBinary() {
      if (Module["locateFile"]) {
        return locateFile("exe.wasm")
      }
      return new URL("exe.wasm", import.meta.url).href
    }

    function getBinarySync(file) {
      if (file == wasmBinaryFile && wasmBinary) {
        return new Uint8Array(wasmBinary)
      }
      if (readBinary) {
        return readBinary(file)
      }
      throw "both async and sync fetching of the wasm failed"
    }
    async function getWasmBinary(binaryFile) {
      if (!wasmBinary) {
        try {
          var response = await readAsync(binaryFile);
          return new Uint8Array(response)
        } catch { }
      }
      return getBinarySync(binaryFile)
    }
    async function instantiateArrayBuffer(binaryFile, imports) {
      try {
        var binary = await getWasmBinary(binaryFile);
        var instance = await WebAssembly.instantiate(binary, imports);
        return instance
      } catch (reason) {
        err(`failed to asynchronously prepare wasm: ${reason}`);
        abort(reason)
      }
    }
    async function instantiateAsync(binary, binaryFile, imports) {
      if (!binary && typeof WebAssembly.instantiateStreaming == "function") {
        try {
          var response = fetch(binaryFile, {
            credentials: "same-origin"
          });
          var instantiationResult = await WebAssembly.instantiateStreaming(response, imports);
          return instantiationResult
        } catch (reason) {
          err(`wasm streaming compile failed: ${reason}`);
          err("falling back to ArrayBuffer instantiation")
        }
      }
      return instantiateArrayBuffer(binaryFile, imports)
    }

    function getWasmImports() {
      assignWasmImports();
      return {
        a: wasmImports
      }
    }
    async function createWasm() {
      function receiveInstance(instance, module) {
        wasmExports = instance.exports;
        registerTLSInit(wasmExports["Cc"]);
        wasmTable = wasmExports["lc"];
        wasmModule = module;
        removeRunDependency("wasm-instantiate");
        return wasmExports
      }
      addRunDependency("wasm-instantiate");

      function receiveInstantiationResult(result) {
        return receiveInstance(result["instance"], result["module"])
      }
      var info = getWasmImports();
      if (Module["instantiateWasm"]) {
        return new Promise((resolve, reject) => {
          Module["instantiateWasm"](info, (mod, inst) => {
            resolve(receiveInstance(mod, inst))
          })
        })
      }
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   return new Promise(resolve => {
      //     wasmModuleReceived = module => {
      //       var instance = new WebAssembly.Instance(module, getWasmImports());
      //       resolve(receiveInstance(instance, module))
      //     }
      //   })
      // }
      wasmBinaryFile ??= findWasmBinary();
      try {
        var result = await instantiateAsync(wasmBinary, wasmBinaryFile, info);
        var exports = receiveInstantiationResult(result);
        return exports
      } catch (e) {
        readyPromiseReject(e);
        return Promise.reject(e)
      }
    }
    class ExitStatus {
      name = "ExitStatus";
      constructor(status) {
        this.message = `Program terminated with exit(${status})`;
        this.status = status
      }
    }
    var terminateWorker = worker => {
      worker.terminate();
      worker.onmessage = e => { }
    };
    var cleanupThread = pthread_ptr => {
      var worker = PThread.pthreads[pthread_ptr];
      PThread.returnWorkerToPool(worker)
    };
    var callRuntimeCallbacks = callbacks => {
      while (callbacks.length > 0) {
        callbacks.shift()(Module)
      }
    };
    var onPreRuns = [];
    var addOnPreRun = cb => onPreRuns.push(cb);
    var spawnThread = threadParams => {
      var worker = PThread.getNewWorker();
      if (!worker) {
        return 6
      }
      PThread.runningWorkers.push(worker);
      PThread.pthreads[threadParams.pthread_ptr] = worker;
      worker.pthread_ptr = threadParams.pthread_ptr;
      var msg = {
        cmd: "run",
        start_routine: threadParams.startRoutine,
        arg: threadParams.arg,
        pthread_ptr: threadParams.pthread_ptr
      };
      worker.postMessage(msg, threadParams.transferList);
      return 0
    };
    var runtimeKeepaliveCounter = 0;
    var keepRuntimeAlive = () => noExitRuntime || runtimeKeepaliveCounter > 0;
    var stackSave = () => _emscripten_stack_get_current();
    var stackRestore = val => __emscripten_stack_restore(val);
    var stackAlloc = sz => __emscripten_stack_alloc(sz);
    var proxyToMainThread = (funcIndex, emAsmAddr, sync, ...callArgs) => {
      var serializedNumCallArgs = callArgs.length * 2;
      var sp = stackSave();
      var args = stackAlloc(serializedNumCallArgs * 8);
      var b = args >> 3;
      for (var i = 0; i < callArgs.length; i++) {
        var arg = callArgs[i];
        if (typeof arg == "bigint") {
          (growMemViews(), HEAP64)[b + 2 * i] = 1n;
          (growMemViews(), HEAP64)[b + 2 * i + 1] = arg
        } else {
          (growMemViews(), HEAP64)[b + 2 * i] = 0n;
          (growMemViews(), HEAPF64)[b + 2 * i + 1] = arg
        }
      }
      var rtn = __emscripten_run_on_main_thread_js(funcIndex, emAsmAddr, serializedNumCallArgs, args, sync);
      stackRestore(sp);
      return rtn
    };

    function _proc_exit(code) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(0, 0, 1, code);
      EXITSTATUS = code;
      if (!keepRuntimeAlive()) {
        PThread.terminateAllThreads();
        Module["onExit"]?.(code);
        ABORT = true
      }
      quit_(code, new ExitStatus(code))
    }
    var runtimeKeepalivePop = () => {
      runtimeKeepaliveCounter -= 1
    };

    function exitOnMainThread(returnCode) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(1, 0, 0, returnCode);
      runtimeKeepalivePop();
      _exit(returnCode)
    }
    var exitJS = (status, implicit) => {
      EXITSTATUS = status;
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   exitOnMainThread(status);
      //   throw "unwind"
      // }
      _proc_exit(status)
    };
    var _exit = exitJS;
    var PThread = {
      unusedWorkers: [],
      runningWorkers: [],
      tlsInitFunctions: [],
      pthreads: {},
      init() {
        // if (!ENVIRONMENT_IS_PTHREAD) {
        //   PThread.initMainThread()
        // }
      },
      initMainThread() {
        var pthreadPoolSize = 10;
        while (pthreadPoolSize--) {
          PThread.allocateUnusedWorker()
        }
        addOnPreRun(() => {
          addRunDependency("loading-workers");
          PThread.loadWasmModuleToAllWorkers(() => removeRunDependency("loading-workers"))
        })
      },
      terminateAllThreads: () => {
        for (var worker of PThread.runningWorkers) {
          terminateWorker(worker)
        }
        for (var worker of PThread.unusedWorkers) {
          terminateWorker(worker)
        }
        PThread.unusedWorkers = [];
        PThread.runningWorkers = [];
        PThread.pthreads = {}
      },
      returnWorkerToPool: worker => {
        var pthread_ptr = worker.pthread_ptr;
        delete PThread.pthreads[pthread_ptr];
        PThread.unusedWorkers.push(worker);
        PThread.runningWorkers.splice(PThread.runningWorkers.indexOf(worker), 1);
        worker.pthread_ptr = 0;
        __emscripten_thread_free_data(pthread_ptr)
      },
      threadInitTLS() {
        PThread.tlsInitFunctions.forEach(f => f())
      },
      loadWasmModuleToWorker: worker => new Promise(onFinishedLoading => {
        worker.onmessage = e => {
          var d = e["data"];
          var cmd = d.cmd;
          if (d.targetThread && d.targetThread != _pthread_self()) {
            var targetWorker = PThread.pthreads[d.targetThread];
            if (targetWorker) {
              targetWorker.postMessage(d, d.transferList)
            } else {
              err(`Internal error! Worker sent a message "${cmd}" to target pthread ${d.targetThread}, but that thread no longer exists!`)
            }
            return
          }
          if (cmd === "checkMailbox") {
            checkMailbox()
          } else if (cmd === "spawnThread") {
            spawnThread(d)
          } else if (cmd === "cleanupThread") {
            cleanupThread(d.thread)
          } else if (cmd === "loaded") {
            worker.loaded = true;
            onFinishedLoading(worker)
          } else if (d.target === "setimmediate") {
            worker.postMessage(d)
          } else if (cmd === "callHandler") {
            Module[d.handler](...d.args)
          } else if (cmd) {
            err(`worker sent an unknown command ${cmd}`)
          }
        };
        worker.onerror = e => {
          var message = "worker sent an error!";
          err(`${message} ${e.filename}:${e.lineno}: ${e.message}`);
          throw e
        };
        var handlers = [];
        var knownHandlers = ["onExit", "onAbort", "print", "printErr"];
        for (var handler of knownHandlers) {
          if (Module.propertyIsEnumerable(handler)) {
            handlers.push(handler)
          }
        }
        worker.postMessage({
          cmd: "load",
          handlers,
          wasmMemory,
          wasmModule
        })
      }),
      loadWasmModuleToAllWorkers(onMaybeReady) {
        // if (ENVIRONMENT_IS_PTHREAD) {
        //   return onMaybeReady()
        // }
        let pthreadPoolReady = Promise.all(PThread.unusedWorkers.map(PThread.loadWasmModuleToWorker));
        pthreadPoolReady.then(onMaybeReady)
      },
      allocateUnusedWorker() {
        var worker;
        if (Module["mainScriptUrlOrBlob"]) {
          var pthreadMainJs = Module["mainScriptUrlOrBlob"];
          if (typeof pthreadMainJs != "string") {
            pthreadMainJs = URL.createObjectURL(pthreadMainJs)
          }
          worker = new Worker(pthreadMainJs, {
            type: "module",
            name: "em-pthread"
          })
        } else worker = new Worker(new URL("exe.js", import.meta.url), {
          type: "module",
          name: "em-pthread"
        });
        PThread.unusedWorkers.push(worker)
      },
      getNewWorker() {
        if (PThread.unusedWorkers.length == 0) {
          PThread.allocateUnusedWorker();
          PThread.loadWasmModuleToWorker(PThread.unusedWorkers[0])
        }
        return PThread.unusedWorkers.pop()
      }
    };
    var onPostRuns = [];
    var addOnPostRun = cb => onPostRuns.push(cb);
    var establishStackSpace = pthread_ptr => {
      var stackHigh = (growMemViews(), HEAPU32)[pthread_ptr + 52 >> 2];
      var stackSize = (growMemViews(), HEAPU32)[pthread_ptr + 56 >> 2];
      var stackLow = stackHigh - stackSize;
      _emscripten_stack_set_limits(stackHigh, stackLow);
      stackRestore(stackHigh)
    };
    var wasmTableMirror = [];
    var wasmTable;
    var getWasmTableEntry = funcPtr => {
      var func = wasmTableMirror[funcPtr];
      if (!func) {
        wasmTableMirror[funcPtr] = func = wasmTable.get(funcPtr)
      }
      return func
    };
    var invokeEntryPoint = (ptr, arg) => {
      runtimeKeepaliveCounter = 0;
      noExitRuntime = 0;
      var result = getWasmTableEntry(ptr)(arg);

      function finish(result) {
        if (keepRuntimeAlive()) {
          EXITSTATUS = result
        } else {
          __emscripten_thread_exit(result)
        }
      }
      finish(result)
    };
    var noExitRuntime = true;
    var registerTLSInit = tlsInitFunc => PThread.tlsInitFunctions.push(tlsInitFunc);
    var runtimeKeepalivePush = () => {
      runtimeKeepaliveCounter += 1
    };
    var UTF8Decoder = typeof TextDecoder != "undefined" ? new TextDecoder : undefined;
    var UTF8ArrayToString = (heapOrArray, idx = 0, maxBytesToRead = NaN) => {
      var endIdx = idx + maxBytesToRead;
      var endPtr = idx;
      while (heapOrArray[endPtr] && !(endPtr >= endIdx)) ++endPtr;
      if (endPtr - idx > 16 && heapOrArray.buffer && UTF8Decoder) {
        return UTF8Decoder.decode(heapOrArray.buffer instanceof ArrayBuffer ? heapOrArray.subarray(idx, endPtr) : heapOrArray.slice(idx, endPtr))
      }
      var str = "";
      while (idx < endPtr) {
        var u0 = heapOrArray[idx++];
        if (!(u0 & 128)) {
          str += String.fromCharCode(u0);
          continue
        }
        var u1 = heapOrArray[idx++] & 63;
        if ((u0 & 224) == 192) {
          str += String.fromCharCode((u0 & 31) << 6 | u1);
          continue
        }
        var u2 = heapOrArray[idx++] & 63;
        if ((u0 & 240) == 224) {
          u0 = (u0 & 15) << 12 | u1 << 6 | u2
        } else {
          u0 = (u0 & 7) << 18 | u1 << 12 | u2 << 6 | heapOrArray[idx++] & 63
        }
        if (u0 < 65536) {
          str += String.fromCharCode(u0)
        } else {
          var ch = u0 - 65536;
          str += String.fromCharCode(55296 | ch >> 10, 56320 | ch & 1023)
        }
      }
      return str
    };
    var UTF8ToString = (ptr, maxBytesToRead) => ptr ? UTF8ArrayToString((growMemViews(), HEAPU8), ptr, maxBytesToRead) : "";
    var ___assert_fail = (condition, filename, line, func) => abort(`Assertion failed: ${UTF8ToString(condition)}, at: ` + [filename ? UTF8ToString(filename) : "unknown filename", line, func ? UTF8ToString(func) : "unknown function"]);
    var ___call_sighandler = (fp, sig) => getWasmTableEntry(fp)(sig);
    class ExceptionInfo {
      constructor(excPtr) {
        this.excPtr = excPtr;
        this.ptr = excPtr - 24
      }
      set_type(type) {
        (growMemViews(), HEAPU32)[this.ptr + 4 >> 2] = type
      }
      get_type() {
        return (growMemViews(), HEAPU32)[this.ptr + 4 >> 2]
      }
      set_destructor(destructor) {
        (growMemViews(), HEAPU32)[this.ptr + 8 >> 2] = destructor
      }
      get_destructor() {
        return (growMemViews(), HEAPU32)[this.ptr + 8 >> 2]
      }
      set_caught(caught) {
        caught = caught ? 1 : 0;
        (growMemViews(), HEAP8)[this.ptr + 12] = caught
      }
      get_caught() {
        return (growMemViews(), HEAP8)[this.ptr + 12] != 0
      }
      set_rethrown(rethrown) {
        rethrown = rethrown ? 1 : 0;
        (growMemViews(), HEAP8)[this.ptr + 13] = rethrown
      }
      get_rethrown() {
        return (growMemViews(), HEAP8)[this.ptr + 13] != 0
      }
      init(type, destructor) {
        this.set_adjusted_ptr(0);
        this.set_type(type);
        this.set_destructor(destructor)
      }
      set_adjusted_ptr(adjustedPtr) {
        (growMemViews(), HEAPU32)[this.ptr + 16 >> 2] = adjustedPtr
      }
      get_adjusted_ptr() {
        return (growMemViews(), HEAPU32)[this.ptr + 16 >> 2]
      }
    }
    var exceptionLast = 0;
    var uncaughtExceptionCount = 0;
    var ___cxa_throw = (ptr, type, destructor) => {
      var info = new ExceptionInfo(ptr);
      info.init(type, destructor);
      exceptionLast = ptr;
      uncaughtExceptionCount++;
      throw exceptionLast
    };

    function pthreadCreateProxied(pthread_ptr, attr, startRoutine, arg) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(2, 0, 1, pthread_ptr, attr, startRoutine, arg);
      return ___pthread_create_js(pthread_ptr, attr, startRoutine, arg)
    }
    var _emscripten_has_threading_support = () => typeof SharedArrayBuffer != "undefined";
    var ___pthread_create_js = (pthread_ptr, attr, startRoutine, arg) => {
      if (!_emscripten_has_threading_support()) {
        return 6
      }
      var transferList = [];
      var error = 0;
      // if (ENVIRONMENT_IS_PTHREAD && (transferList.length === 0 || error)) {
      //   return pthreadCreateProxied(pthread_ptr, attr, startRoutine, arg)
      // }
      if (error) return error;
      var threadParams = {
        startRoutine,
        pthread_ptr,
        arg,
        transferList
      };
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   threadParams.cmd = "spawnThread";
      //   postMessage(threadParams, transferList);
      //   return 0
      // }
      return spawnThread(threadParams)
    };
    var PATH = {
      isAbs: path => path.charAt(0) === "/",
      splitPath: filename => {
        var splitPathRe = /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;
        return splitPathRe.exec(filename).slice(1)
      },
      normalizeArray: (parts, allowAboveRoot) => {
        var up = 0;
        for (var i = parts.length - 1; i >= 0; i--) {
          var last = parts[i];
          if (last === ".") {
            parts.splice(i, 1)
          } else if (last === "..") {
            parts.splice(i, 1);
            up++
          } else if (up) {
            parts.splice(i, 1);
            up--
          }
        }
        if (allowAboveRoot) {
          for (; up; up--) {
            parts.unshift("..")
          }
        }
        return parts
      },
      normalize: path => {
        var isAbsolute = PATH.isAbs(path),
          trailingSlash = path.slice(-1) === "/";
        path = PATH.normalizeArray(path.split("/").filter(p => !!p), !isAbsolute).join("/");
        if (!path && !isAbsolute) {
          path = "."
        }
        if (path && trailingSlash) {
          path += "/"
        }
        return (isAbsolute ? "/" : "") + path
      },
      dirname: path => {
        var result = PATH.splitPath(path),
          root = result[0],
          dir = result[1];
        if (!root && !dir) {
          return "."
        }
        if (dir) {
          dir = dir.slice(0, -1)
        }
        return root + dir
      },
      basename: path => path && path.match(/([^\/]+|\/)\/*$/)[1],
      join: (...paths) => PATH.normalize(paths.join("/")),
      join2: (l, r) => PATH.normalize(l + "/" + r)
    };
    var initRandomFill = () => view => view.set(crypto.getRandomValues(new Uint8Array(view.byteLength)));
    var randomFill = view => {
      (randomFill = initRandomFill())(view)
    };
    var PATH_FS = {
      resolve: (...args) => {
        var resolvedPath = "",
          resolvedAbsolute = false;
        for (var i = args.length - 1; i >= -1 && !resolvedAbsolute; i--) {
          var path = i >= 0 ? args[i] : FS.cwd();
          if (typeof path != "string") {
            throw new TypeError("Arguments to path.resolve must be strings")
          } else if (!path) {
            return ""
          }
          resolvedPath = path + "/" + resolvedPath;
          resolvedAbsolute = PATH.isAbs(path)
        }
        resolvedPath = PATH.normalizeArray(resolvedPath.split("/").filter(p => !!p), !resolvedAbsolute).join("/");
        return (resolvedAbsolute ? "/" : "") + resolvedPath || "."
      },
      relative: (from, to) => {
        from = PATH_FS.resolve(from).slice(1);
        to = PATH_FS.resolve(to).slice(1);

        function trim(arr) {
          var start = 0;
          for (; start < arr.length; start++) {
            if (arr[start] !== "") break
          }
          var end = arr.length - 1;
          for (; end >= 0; end--) {
            if (arr[end] !== "") break
          }
          if (start > end) return [];
          return arr.slice(start, end - start + 1)
        }
        var fromParts = trim(from.split("/"));
        var toParts = trim(to.split("/"));
        var length = Math.min(fromParts.length, toParts.length);
        var samePartsLength = length;
        for (var i = 0; i < length; i++) {
          if (fromParts[i] !== toParts[i]) {
            samePartsLength = i;
            break
          }
        }
        var outputParts = [];
        for (var i = samePartsLength; i < fromParts.length; i++) {
          outputParts.push("..")
        }
        outputParts = outputParts.concat(toParts.slice(samePartsLength));
        return outputParts.join("/")
      }
    };
    var PTY_signalNameToCode = {
      SIGINT: 2,
      SIGQUIT: 3,
      SIGTSTP: 20,
      SIGWINCH: 28
    };
    var PTY = Module["pty"];
    var PTY_pollTimeout = 0;
    var PTY_askToWaitAgain = timeout => {
      PTY_pollTimeout = timeout;
      throw new FS.ErrnoError(1006)
    };
    var TTY = {
      ttys: [],
      init() { },
      shutdown() { },
      register(dev, ops) {
        TTY.ttys[dev] = {
          input: [],
          output: [],
          ops
        };
        FS.registerDevice(dev, TTY.stream_ops)
      },
      stream_ops: {
        open(stream) {
          var tty = TTY.ttys[stream.node.rdev];
          if (!tty) {
            throw new FS.ErrnoError(43)
          }
          stream.tty = tty;
          stream.seekable = false
        },
        close(stream) {
          stream.tty.ops.fsync(stream.tty)
        },
        fsync(stream) {
          stream.tty.ops.fsync(stream.tty)
        },
        read: (stream, buffer, offset, length) => {
          let readBytes = PTY.read(length);
          if (length && !readBytes.length) {
            PTY_askToWaitAgain(-1)
          }
          buffer.set(readBytes, offset);
          return readBytes.length
        },
        write: (stream, buffer, offset, length) => {
          if (buffer === (growMemViews(), HEAP8)) {
            buffer = (growMemViews(), HEAPU8)
          } else if (!(buffer instanceof Uint8Array)) {
            throw new Error(`Unexpected buffer type: ${buffer.constructor.name}`)
          }
          PTY.write(Array.from(buffer.subarray(offset, offset + length)));
          return length
        },
        poll: (stream, timeout) => {
          if (!PTY.readable && timeout) {
            PTY_askToWaitAgain(timeout)
          }
          return (PTY.readable ? 1 : 0) | (PTY.writable ? 4 : 0)
        }
      },
      default_tty_ops: {
        get_char: () => { },
        put_char: () => { },
        fsync: () => { },
        ioctl_tcgets: () => {
          const termios = PTY.ioctl("TCGETS");
          const data = {
            c_iflag: termios.iflag,
            c_oflag: termios.oflag,
            c_cflag: termios.cflag,
            c_lflag: termios.lflag,
            c_cc: termios.cc
          };
          return data
        },
        ioctl_tcsets: (_tty, _optional_actions, data) => {
          PTY.ioctl("TCSETS", {
            iflag: data.c_iflag,
            oflag: data.c_oflag,
            cflag: data.c_cflag,
            lflag: data.c_lflag,
            cc: data.c_cc
          });
          return 0
        },
        ioctl_tiocgwinsz: () => PTY.ioctl("TIOCGWINSZ").reverse()
      },
      default_tty1_ops: {
        put_char: () => { },
        fsync: () => { }
      }
    };
    var mmapAlloc = size => {
      abort()
    };
    var MEMFS = {
      ops_table: null,
      mount(mount) {
        return MEMFS.createNode(null, "/", 16895, 0)
      },
      createNode(parent, name, mode, dev) {
        if (FS.isBlkdev(mode) || FS.isFIFO(mode)) {
          throw new FS.ErrnoError(63)
        }
        MEMFS.ops_table ||= {
          dir: {
            node: {
              getattr: MEMFS.node_ops.getattr,
              setattr: MEMFS.node_ops.setattr,
              lookup: MEMFS.node_ops.lookup,
              mknod: MEMFS.node_ops.mknod,
              rename: MEMFS.node_ops.rename,
              unlink: MEMFS.node_ops.unlink,
              rmdir: MEMFS.node_ops.rmdir,
              readdir: MEMFS.node_ops.readdir,
              symlink: MEMFS.node_ops.symlink
            },
            stream: {
              llseek: MEMFS.stream_ops.llseek
            }
          },
          file: {
            node: {
              getattr: MEMFS.node_ops.getattr,
              setattr: MEMFS.node_ops.setattr
            },
            stream: {
              llseek: MEMFS.stream_ops.llseek,
              read: MEMFS.stream_ops.read,
              write: MEMFS.stream_ops.write,
              mmap: MEMFS.stream_ops.mmap,
              msync: MEMFS.stream_ops.msync
            }
          },
          link: {
            node: {
              getattr: MEMFS.node_ops.getattr,
              setattr: MEMFS.node_ops.setattr,
              readlink: MEMFS.node_ops.readlink
            },
            stream: {}
          },
          chrdev: {
            node: {
              getattr: MEMFS.node_ops.getattr,
              setattr: MEMFS.node_ops.setattr
            },
            stream: FS.chrdev_stream_ops
          }
        };
        var node = FS.createNode(parent, name, mode, dev);
        if (FS.isDir(node.mode)) {
          node.node_ops = MEMFS.ops_table.dir.node;
          node.stream_ops = MEMFS.ops_table.dir.stream;
          node.contents = {}
        } else if (FS.isFile(node.mode)) {
          node.node_ops = MEMFS.ops_table.file.node;
          node.stream_ops = MEMFS.ops_table.file.stream;
          node.usedBytes = 0;
          node.contents = null
        } else if (FS.isLink(node.mode)) {
          node.node_ops = MEMFS.ops_table.link.node;
          node.stream_ops = MEMFS.ops_table.link.stream
        } else if (FS.isChrdev(node.mode)) {
          node.node_ops = MEMFS.ops_table.chrdev.node;
          node.stream_ops = MEMFS.ops_table.chrdev.stream
        }
        node.atime = node.mtime = node.ctime = Date.now();
        if (parent) {
          parent.contents[name] = node;
          parent.atime = parent.mtime = parent.ctime = node.atime
        }
        return node
      },
      getFileDataAsTypedArray(node) {
        if (!node.contents) return new Uint8Array(0);
        if (node.contents.subarray) return node.contents.subarray(0, node.usedBytes);
        return new Uint8Array(node.contents)
      },
      expandFileStorage(node, newCapacity) {
        var prevCapacity = node.contents ? node.contents.length : 0;
        if (prevCapacity >= newCapacity) return;
        var CAPACITY_DOUBLING_MAX = 1024 * 1024;
        newCapacity = Math.max(newCapacity, prevCapacity * (prevCapacity < CAPACITY_DOUBLING_MAX ? 2 : 1.125) >>> 0);
        if (prevCapacity != 0) newCapacity = Math.max(newCapacity, 256);
        var oldContents = node.contents;
        node.contents = new Uint8Array(newCapacity);
        if (node.usedBytes > 0) node.contents.set(oldContents.subarray(0, node.usedBytes), 0)
      },
      resizeFileStorage(node, newSize) {
        if (node.usedBytes == newSize) return;
        if (newSize == 0) {
          node.contents = null;
          node.usedBytes = 0
        } else {
          var oldContents = node.contents;
          node.contents = new Uint8Array(newSize);
          if (oldContents) {
            node.contents.set(oldContents.subarray(0, Math.min(newSize, node.usedBytes)))
          }
          node.usedBytes = newSize
        }
      },
      node_ops: {
        getattr(node) {
          var attr = {};
          attr.dev = FS.isChrdev(node.mode) ? node.id : 1;
          attr.ino = node.id;
          attr.mode = node.mode;
          attr.nlink = 1;
          attr.uid = 0;
          attr.gid = 0;
          attr.rdev = node.rdev;
          if (FS.isDir(node.mode)) {
            attr.size = 4096
          } else if (FS.isFile(node.mode)) {
            attr.size = node.usedBytes
          } else if (FS.isLink(node.mode)) {
            attr.size = node.link.length
          } else {
            attr.size = 0
          }
          attr.atime = new Date(node.atime);
          attr.mtime = new Date(node.mtime);
          attr.ctime = new Date(node.ctime);
          attr.blksize = 4096;
          attr.blocks = Math.ceil(attr.size / attr.blksize);
          return attr
        },
        setattr(node, attr) {
          for (const key of ["mode", "atime", "mtime", "ctime"]) {
            if (attr[key] != null) {
              node[key] = attr[key]
            }
          }
          if (attr.size !== undefined) {
            MEMFS.resizeFileStorage(node, attr.size)
          }
        },
        lookup(parent, name) {
          throw MEMFS.doesNotExistError
        },
        mknod(parent, name, mode, dev) {
          return MEMFS.createNode(parent, name, mode, dev)
        },
        rename(old_node, new_dir, new_name) {
          var new_node;
          try {
            new_node = FS.lookupNode(new_dir, new_name)
          } catch (e) { }
          if (new_node) {
            if (FS.isDir(old_node.mode)) {
              for (var i in new_node.contents) {
                throw new FS.ErrnoError(55)
              }
            }
            FS.hashRemoveNode(new_node)
          }
          delete old_node.parent.contents[old_node.name];
          new_dir.contents[new_name] = old_node;
          old_node.name = new_name;
          new_dir.ctime = new_dir.mtime = old_node.parent.ctime = old_node.parent.mtime = Date.now()
        },
        unlink(parent, name) {
          delete parent.contents[name];
          parent.ctime = parent.mtime = Date.now()
        },
        rmdir(parent, name) {
          var node = FS.lookupNode(parent, name);
          for (var i in node.contents) {
            throw new FS.ErrnoError(55)
          }
          delete parent.contents[name];
          parent.ctime = parent.mtime = Date.now()
        },
        readdir(node) {
          return [".", "..", ...Object.keys(node.contents)]
        },
        symlink(parent, newname, oldpath) {
          var node = MEMFS.createNode(parent, newname, 511 | 40960, 0);
          node.link = oldpath;
          return node
        },
        readlink(node) {
          if (!FS.isLink(node.mode)) {
            throw new FS.ErrnoError(28)
          }
          return node.link
        }
      },
      stream_ops: {
        read(stream, buffer, offset, length, position) {
          var contents = stream.node.contents;
          if (position >= stream.node.usedBytes) return 0;
          var size = Math.min(stream.node.usedBytes - position, length);
          if (size > 8 && contents.subarray) {
            buffer.set(contents.subarray(position, position + size), offset)
          } else {
            for (var i = 0; i < size; i++) buffer[offset + i] = contents[position + i]
          }
          return size
        },
        write(stream, buffer, offset, length, position, canOwn) {
          if (buffer.buffer === (growMemViews(), HEAP8).buffer) {
            canOwn = false
          }
          if (!length) return 0;
          var node = stream.node;
          node.mtime = node.ctime = Date.now();
          if (buffer.subarray && (!node.contents || node.contents.subarray)) {
            if (canOwn) {
              node.contents = buffer.subarray(offset, offset + length);
              node.usedBytes = length;
              return length
            } else if (node.usedBytes === 0 && position === 0) {
              node.contents = buffer.slice(offset, offset + length);
              node.usedBytes = length;
              return length
            } else if (position + length <= node.usedBytes) {
              node.contents.set(buffer.subarray(offset, offset + length), position);
              return length
            }
          }
          MEMFS.expandFileStorage(node, position + length);
          if (node.contents.subarray && buffer.subarray) {
            node.contents.set(buffer.subarray(offset, offset + length), position)
          } else {
            for (var i = 0; i < length; i++) {
              node.contents[position + i] = buffer[offset + i]
            }
          }
          node.usedBytes = Math.max(node.usedBytes, position + length);
          return length
        },
        llseek(stream, offset, whence) {
          var position = offset;
          if (whence === 1) {
            position += stream.position
          } else if (whence === 2) {
            if (FS.isFile(stream.node.mode)) {
              position += stream.node.usedBytes
            }
          }
          if (position < 0) {
            throw new FS.ErrnoError(28)
          }
          return position
        },
        mmap(stream, length, position, prot, flags) {
          if (!FS.isFile(stream.node.mode)) {
            throw new FS.ErrnoError(43)
          }
          var ptr;
          var allocated;
          var contents = stream.node.contents;
          if (!(flags & 2) && contents && contents.buffer === (growMemViews(), HEAP8).buffer) {
            allocated = false;
            ptr = contents.byteOffset
          } else {
            allocated = true;
            ptr = mmapAlloc(length);
            if (!ptr) {
              throw new FS.ErrnoError(48)
            }
            if (contents) {
              if (position > 0 || position + length < contents.length) {
                if (contents.subarray) {
                  contents = contents.subarray(position, position + length)
                } else {
                  contents = Array.prototype.slice.call(contents, position, position + length)
                }
              } (growMemViews(), HEAP8).set(contents, ptr)
            }
          }
          return {
            ptr,
            allocated
          }
        },
        msync(stream, buffer, offset, length, mmapFlags) {
          MEMFS.stream_ops.write(stream, buffer, 0, length, offset, false);
          return 0
        }
      }
    };
    var asyncLoad = async url => {
      var arrayBuffer = await readAsync(url);
      return new Uint8Array(arrayBuffer)
    };
    var FS_createDataFile = (...args) => FS.createDataFile(...args);
    var preloadPlugins = [];
    var FS_handledByPreloadPlugin = (byteArray, fullname, finish, onerror) => {
      if (typeof Browser != "undefined") Browser.init();
      var handled = false;
      preloadPlugins.forEach(plugin => {
        if (handled) return;
        if (plugin["canHandle"](fullname)) {
          plugin["handle"](byteArray, fullname, finish, onerror);
          handled = true
        }
      });
      return handled
    };
    var FS_createPreloadedFile = (parent, name, url, canRead, canWrite, onload, onerror, dontCreateFile, canOwn, preFinish) => {
      var fullname = name ? PATH_FS.resolve(PATH.join2(parent, name)) : parent;
      var dep = getUniqueRunDependency(`cp ${fullname}`);

      function processData(byteArray) {
        function finish(byteArray) {
          preFinish?.();
          if (!dontCreateFile) {
            FS_createDataFile(parent, name, byteArray, canRead, canWrite, canOwn)
          }
          onload?.();
          removeRunDependency(dep)
        }
        if (FS_handledByPreloadPlugin(byteArray, fullname, finish, () => {
          onerror?.();
          removeRunDependency(dep)
        })) {
          return
        }
        finish(byteArray)
      }
      addRunDependency(dep);
      if (typeof url == "string") {
        asyncLoad(url).then(processData, onerror)
      } else {
        processData(url)
      }
    };
    var FS_modeStringToFlags = str => {
      var flagModes = {
        r: 0,
        "r+": 2,
        w: 512 | 64 | 1,
        "w+": 512 | 64 | 2,
        a: 1024 | 64 | 1,
        "a+": 1024 | 64 | 2
      };
      var flags = flagModes[str];
      if (typeof flags == "undefined") {
        throw new Error(`Unknown file open mode: ${str}`)
      }
      return flags
    };
    var FS_getMode = (canRead, canWrite) => {
      var mode = 0;
      if (canRead) mode |= 292 | 73;
      if (canWrite) mode |= 146;
      return mode
    };
    var lengthBytesUTF8 = str => {
      var len = 0;
      for (var i = 0; i < str.length; ++i) {
        var c = str.charCodeAt(i);
        if (c <= 127) {
          len++
        } else if (c <= 2047) {
          len += 2
        } else if (c >= 55296 && c <= 57343) {
          len += 4;
          ++i
        } else {
          len += 3
        }
      }
      return len
    };
    var stringToUTF8Array = (str, heap, outIdx, maxBytesToWrite) => {
      if (!(maxBytesToWrite > 0)) return 0;
      var startIdx = outIdx;
      var endIdx = outIdx + maxBytesToWrite - 1;
      for (var i = 0; i < str.length; ++i) {
        var u = str.charCodeAt(i);
        if (u >= 55296 && u <= 57343) {
          var u1 = str.charCodeAt(++i);
          u = 65536 + ((u & 1023) << 10) | u1 & 1023
        }
        if (u <= 127) {
          if (outIdx >= endIdx) break;
          heap[outIdx++] = u
        } else if (u <= 2047) {
          if (outIdx + 1 >= endIdx) break;
          heap[outIdx++] = 192 | u >> 6;
          heap[outIdx++] = 128 | u & 63
        } else if (u <= 65535) {
          if (outIdx + 2 >= endIdx) break;
          heap[outIdx++] = 224 | u >> 12;
          heap[outIdx++] = 128 | u >> 6 & 63;
          heap[outIdx++] = 128 | u & 63
        } else {
          if (outIdx + 3 >= endIdx) break;
          heap[outIdx++] = 240 | u >> 18;
          heap[outIdx++] = 128 | u >> 12 & 63;
          heap[outIdx++] = 128 | u >> 6 & 63;
          heap[outIdx++] = 128 | u & 63
        }
      }
      heap[outIdx] = 0;
      return outIdx - startIdx
    };
    var intArrayFromString = (stringy, dontAddNull, length) => {
      var len = length > 0 ? length : lengthBytesUTF8(stringy) + 1;
      var u8array = new Array(len);
      var numBytesWritten = stringToUTF8Array(stringy, u8array, 0, u8array.length);
      if (dontAddNull) u8array.length = numBytesWritten;
      return u8array
    };
    var FS = {
      root: null,
      mounts: [],
      devices: {},
      streams: [],
      nextInode: 1,
      nameTable: null,
      currentPath: "/",
      initialized: false,
      ignorePermissions: true,
      filesystems: null,
      syncFSRequests: 0,
      readFiles: {},
      ErrnoError: class {
        name = "ErrnoError";
        constructor(errno) {
          this.errno = errno
        }
      },
      FSStream: class {
        shared = {};
        get object() {
          return this.node
        }
        set object(val) {
          this.node = val
        }
        get isRead() {
          return (this.flags & 2097155) !== 1
        }
        get isWrite() {
          return (this.flags & 2097155) !== 0
        }
        get isAppend() {
          return this.flags & 1024
        }
        get flags() {
          return this.shared.flags
        }
        set flags(val) {
          this.shared.flags = val
        }
        get position() {
          return this.shared.position
        }
        set position(val) {
          this.shared.position = val
        }
      },
      FSNode: class {
        node_ops = {};
        stream_ops = {};
        readMode = 292 | 73;
        writeMode = 146;
        mounted = null;
        constructor(parent, name, mode, rdev) {
          if (!parent) {
            parent = this
          }
          this.parent = parent;
          this.mount = parent.mount;
          this.id = FS.nextInode++;
          this.name = name;
          this.mode = mode;
          this.rdev = rdev;
          this.atime = this.mtime = this.ctime = Date.now()
        }
        get read() {
          return (this.mode & this.readMode) === this.readMode
        }
        set read(val) {
          val ? this.mode |= this.readMode : this.mode &= ~this.readMode
        }
        get write() {
          return (this.mode & this.writeMode) === this.writeMode
        }
        set write(val) {
          val ? this.mode |= this.writeMode : this.mode &= ~this.writeMode
        }
        get isFolder() {
          return FS.isDir(this.mode)
        }
        get isDevice() {
          return FS.isChrdev(this.mode)
        }
      },
      lookupPath(path, opts = {}) {
        if (!path) {
          throw new FS.ErrnoError(44)
        }
        opts.follow_mount ??= true;
        if (!PATH.isAbs(path)) {
          path = FS.cwd() + "/" + path
        }
        linkloop: for (var nlinks = 0; nlinks < 40; nlinks++) {
          var parts = path.split("/").filter(p => !!p);
          var current = FS.root;
          var current_path = "/";
          for (var i = 0; i < parts.length; i++) {
            var islast = i === parts.length - 1;
            if (islast && opts.parent) {
              break
            }
            if (parts[i] === ".") {
              continue
            }
            if (parts[i] === "..") {
              current_path = PATH.dirname(current_path);
              if (FS.isRoot(current)) {
                path = current_path + "/" + parts.slice(i + 1).join("/");
                continue linkloop
              } else {
                current = current.parent
              }
              continue
            }
            current_path = PATH.join2(current_path, parts[i]);
            try {
              current = FS.lookupNode(current, parts[i])
            } catch (e) {
              if (e?.errno === 44 && islast && opts.noent_okay) {
                return {
                  path: current_path
                }
              }
              throw e
            }
            if (FS.isMountpoint(current) && (!islast || opts.follow_mount)) {
              current = current.mounted.root
            }
            if (FS.isLink(current.mode) && (!islast || opts.follow)) {
              if (!current.node_ops.readlink) {
                throw new FS.ErrnoError(52)
              }
              var link = current.node_ops.readlink(current);
              if (!PATH.isAbs(link)) {
                link = PATH.dirname(current_path) + "/" + link
              }
              path = link + "/" + parts.slice(i + 1).join("/");
              continue linkloop
            }
          }
          return {
            path: current_path,
            node: current
          }
        }
        throw new FS.ErrnoError(32)
      },
      getPath(node) {
        var path;
        while (true) {
          if (FS.isRoot(node)) {
            var mount = node.mount.mountpoint;
            if (!path) return mount;
            return mount[mount.length - 1] !== "/" ? `${mount}/${path}` : mount + path
          }
          path = path ? `${node.name}/${path}` : node.name;
          node = node.parent
        }
      },
      hashName(parentid, name) {
        var hash = 0;
        for (var i = 0; i < name.length; i++) {
          hash = (hash << 5) - hash + name.charCodeAt(i) | 0
        }
        return (parentid + hash >>> 0) % FS.nameTable.length
      },
      hashAddNode(node) {
        var hash = FS.hashName(node.parent.id, node.name);
        node.name_next = FS.nameTable[hash];
        FS.nameTable[hash] = node
      },
      hashRemoveNode(node) {
        var hash = FS.hashName(node.parent.id, node.name);
        if (FS.nameTable[hash] === node) {
          FS.nameTable[hash] = node.name_next
        } else {
          var current = FS.nameTable[hash];
          while (current) {
            if (current.name_next === node) {
              current.name_next = node.name_next;
              break
            }
            current = current.name_next
          }
        }
      },
      lookupNode(parent, name) {
        var errCode = FS.mayLookup(parent);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        var hash = FS.hashName(parent.id, name);
        for (var node = FS.nameTable[hash]; node; node = node.name_next) {
          var nodeName = node.name;
          if (node.parent.id === parent.id && nodeName === name) {
            return node
          }
        }
        return FS.lookup(parent, name)
      },
      createNode(parent, name, mode, rdev) {
        var node = new FS.FSNode(parent, name, mode, rdev);
        FS.hashAddNode(node);
        return node
      },
      destroyNode(node) {
        FS.hashRemoveNode(node)
      },
      isRoot(node) {
        return node === node.parent
      },
      isMountpoint(node) {
        return !!node.mounted
      },
      isFile(mode) {
        return (mode & 61440) === 32768
      },
      isDir(mode) {
        return (mode & 61440) === 16384
      },
      isLink(mode) {
        return (mode & 61440) === 40960
      },
      isChrdev(mode) {
        return (mode & 61440) === 8192
      },
      isBlkdev(mode) {
        return (mode & 61440) === 24576
      },
      isFIFO(mode) {
        return (mode & 61440) === 4096
      },
      isSocket(mode) {
        return (mode & 49152) === 49152
      },
      flagsToPermissionString(flag) {
        var perms = ["r", "w", "rw"][flag & 3];
        if (flag & 512) {
          perms += "w"
        }
        return perms
      },
      nodePermissions(node, perms) {
        if (FS.ignorePermissions) {
          return 0
        }
        if (perms.includes("r") && !(node.mode & 292)) {
          return 2
        } else if (perms.includes("w") && !(node.mode & 146)) {
          return 2
        } else if (perms.includes("x") && !(node.mode & 73)) {
          return 2
        }
        return 0
      },
      mayLookup(dir) {
        if (!FS.isDir(dir.mode)) return 54;
        var errCode = FS.nodePermissions(dir, "x");
        if (errCode) return errCode;
        if (!dir.node_ops.lookup) return 2;
        return 0
      },
      mayCreate(dir, name) {
        if (!FS.isDir(dir.mode)) {
          return 54
        }
        try {
          var node = FS.lookupNode(dir, name);
          return 20
        } catch (e) { }
        return FS.nodePermissions(dir, "wx")
      },
      mayDelete(dir, name, isdir) {
        var node;
        try {
          node = FS.lookupNode(dir, name)
        } catch (e) {
          return e.errno
        }
        var errCode = FS.nodePermissions(dir, "wx");
        if (errCode) {
          return errCode
        }
        if (isdir) {
          if (!FS.isDir(node.mode)) {
            return 54
          }
          if (FS.isRoot(node) || FS.getPath(node) === FS.cwd()) {
            return 10
          }
        } else {
          if (FS.isDir(node.mode)) {
            return 31
          }
        }
        return 0
      },
      mayOpen(node, flags) {
        if (!node) {
          return 44
        }
        if (FS.isLink(node.mode)) {
          return 32
        } else if (FS.isDir(node.mode)) {
          if (FS.flagsToPermissionString(flags) !== "r" || flags & (512 | 64)) {
            return 31
          }
        }
        return FS.nodePermissions(node, FS.flagsToPermissionString(flags))
      },
      checkOpExists(op, err) {
        if (!op) {
          throw new FS.ErrnoError(err)
        }
        return op
      },
      MAX_OPEN_FDS: 4096,
      nextfd() {
        for (var fd = 0; fd <= FS.MAX_OPEN_FDS; fd++) {
          if (!FS.streams[fd]) {
            return fd
          }
        }
        throw new FS.ErrnoError(33)
      },
      getStreamChecked(fd) {
        var stream = FS.getStream(fd);
        if (!stream) {
          throw new FS.ErrnoError(8)
        }
        return stream
      },
      getStream: fd => FS.streams[fd],
      createStream(stream, fd = -1) {
        stream = Object.assign(new FS.FSStream, stream);
        if (fd == -1) {
          fd = FS.nextfd()
        }
        stream.fd = fd;
        FS.streams[fd] = stream;
        return stream
      },
      closeStream(fd) {
        FS.streams[fd] = null
      },
      dupStream(origStream, fd = -1) {
        var stream = FS.createStream(origStream, fd);
        stream.stream_ops?.dup?.(stream);
        return stream
      },
      doSetAttr(stream, node, attr) {
        var setattr = stream?.stream_ops.setattr;
        var arg = setattr ? stream : node;
        setattr ??= node.node_ops.setattr;
        FS.checkOpExists(setattr, 63);
        setattr(arg, attr)
      },
      chrdev_stream_ops: {
        open(stream) {
          var device = FS.getDevice(stream.node.rdev);
          stream.stream_ops = device.stream_ops;
          stream.stream_ops.open?.(stream)
        },
        llseek() {
          throw new FS.ErrnoError(70)
        }
      },
      major: dev => dev >> 8,
      minor: dev => dev & 255,
      makedev: (ma, mi) => ma << 8 | mi,
      registerDevice(dev, ops) {
        FS.devices[dev] = {
          stream_ops: ops
        }
      },
      getDevice: dev => FS.devices[dev],
      getMounts(mount) {
        var mounts = [];
        var check = [mount];
        while (check.length) {
          var m = check.pop();
          mounts.push(m);
          check.push(...m.mounts)
        }
        return mounts
      },
      syncfs(populate, callback) {
        if (typeof populate == "function") {
          callback = populate;
          populate = false
        }
        FS.syncFSRequests++;
        if (FS.syncFSRequests > 1) {
          err(`warning: ${FS.syncFSRequests} FS.syncfs operations in flight at once, probably just doing extra work`)
        }
        var mounts = FS.getMounts(FS.root.mount);
        var completed = 0;

        function doCallback(errCode) {
          FS.syncFSRequests--;
          return callback(errCode)
        }

        function done(errCode) {
          if (errCode) {
            if (!done.errored) {
              done.errored = true;
              return doCallback(errCode)
            }
            return
          }
          if (++completed >= mounts.length) {
            doCallback(null)
          }
        }
        mounts.forEach(mount => {
          if (!mount.type.syncfs) {
            return done(null)
          }
          mount.type.syncfs(mount, populate, done)
        })
      },
      mount(type, opts, mountpoint) {
        var root = mountpoint === "/";
        var pseudo = !mountpoint;
        var node;
        if (root && FS.root) {
          throw new FS.ErrnoError(10)
        } else if (!root && !pseudo) {
          var lookup = FS.lookupPath(mountpoint, {
            follow_mount: false
          });
          mountpoint = lookup.path;
          node = lookup.node;
          if (FS.isMountpoint(node)) {
            throw new FS.ErrnoError(10)
          }
          if (!FS.isDir(node.mode)) {
            throw new FS.ErrnoError(54)
          }
        }
        var mount = {
          type,
          opts,
          mountpoint,
          mounts: []
        };
        var mountRoot = type.mount(mount);
        mountRoot.mount = mount;
        mount.root = mountRoot;
        if (root) {
          FS.root = mountRoot
        } else if (node) {
          node.mounted = mount;
          if (node.mount) {
            node.mount.mounts.push(mount)
          }
        }
        return mountRoot
      },
      unmount(mountpoint) {
        var lookup = FS.lookupPath(mountpoint, {
          follow_mount: false
        });
        if (!FS.isMountpoint(lookup.node)) {
          throw new FS.ErrnoError(28)
        }
        var node = lookup.node;
        var mount = node.mounted;
        var mounts = FS.getMounts(mount);
        Object.keys(FS.nameTable).forEach(hash => {
          var current = FS.nameTable[hash];
          while (current) {
            var next = current.name_next;
            if (mounts.includes(current.mount)) {
              FS.destroyNode(current)
            }
            current = next
          }
        });
        node.mounted = null;
        var idx = node.mount.mounts.indexOf(mount);
        node.mount.mounts.splice(idx, 1)
      },
      lookup(parent, name) {
        return parent.node_ops.lookup(parent, name)
      },
      mknod(path, mode, dev) {
        var lookup = FS.lookupPath(path, {
          parent: true
        });
        var parent = lookup.node;
        var name = PATH.basename(path);
        if (!name) {
          throw new FS.ErrnoError(28)
        }
        if (name === "." || name === "..") {
          throw new FS.ErrnoError(20)
        }
        var errCode = FS.mayCreate(parent, name);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        if (!parent.node_ops.mknod) {
          throw new FS.ErrnoError(63)
        }
        return parent.node_ops.mknod(parent, name, mode, dev)
      },
      statfs(path) {
        return FS.statfsNode(FS.lookupPath(path, {
          follow: true
        }).node)
      },
      statfsStream(stream) {
        return FS.statfsNode(stream.node)
      },
      statfsNode(node) {
        var rtn = {
          bsize: 4096,
          frsize: 4096,
          blocks: 1e6,
          bfree: 5e5,
          bavail: 5e5,
          files: FS.nextInode,
          ffree: FS.nextInode - 1,
          fsid: 42,
          flags: 2,
          namelen: 255
        };
        if (node.node_ops.statfs) {
          Object.assign(rtn, node.node_ops.statfs(node.mount.opts.root))
        }
        return rtn
      },
      create(path, mode = 438) {
        mode &= 4095;
        mode |= 32768;
        return FS.mknod(path, mode, 0)
      },
      mkdir(path, mode = 511) {
        mode &= 511 | 512;
        mode |= 16384;
        return FS.mknod(path, mode, 0)
      },
      mkdirTree(path, mode) {
        var dirs = path.split("/");
        var d = "";
        for (var dir of dirs) {
          if (!dir) continue;
          if (d || PATH.isAbs(path)) d += "/";
          d += dir;
          try {
            FS.mkdir(d, mode)
          } catch (e) {
            if (e.errno != 20) throw e
          }
        }
      },
      mkdev(path, mode, dev) {
        if (typeof dev == "undefined") {
          dev = mode;
          mode = 438
        }
        mode |= 8192;
        return FS.mknod(path, mode, dev)
      },
      symlink(oldpath, newpath) {
        if (!PATH_FS.resolve(oldpath)) {
          throw new FS.ErrnoError(44)
        }
        var lookup = FS.lookupPath(newpath, {
          parent: true
        });
        var parent = lookup.node;
        if (!parent) {
          throw new FS.ErrnoError(44)
        }
        var newname = PATH.basename(newpath);
        var errCode = FS.mayCreate(parent, newname);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        if (!parent.node_ops.symlink) {
          throw new FS.ErrnoError(63)
        }
        return parent.node_ops.symlink(parent, newname, oldpath)
      },
      rename(old_path, new_path) {
        var old_dirname = PATH.dirname(old_path);
        var new_dirname = PATH.dirname(new_path);
        var old_name = PATH.basename(old_path);
        var new_name = PATH.basename(new_path);
        var lookup, old_dir, new_dir;
        lookup = FS.lookupPath(old_path, {
          parent: true
        });
        old_dir = lookup.node;
        lookup = FS.lookupPath(new_path, {
          parent: true
        });
        new_dir = lookup.node;
        if (!old_dir || !new_dir) throw new FS.ErrnoError(44);
        if (old_dir.mount !== new_dir.mount) {
          throw new FS.ErrnoError(75)
        }
        var old_node = FS.lookupNode(old_dir, old_name);
        var relative = PATH_FS.relative(old_path, new_dirname);
        if (relative.charAt(0) !== ".") {
          throw new FS.ErrnoError(28)
        }
        relative = PATH_FS.relative(new_path, old_dirname);
        if (relative.charAt(0) !== ".") {
          throw new FS.ErrnoError(55)
        }
        var new_node;
        try {
          new_node = FS.lookupNode(new_dir, new_name)
        } catch (e) { }
        if (old_node === new_node) {
          return
        }
        var isdir = FS.isDir(old_node.mode);
        var errCode = FS.mayDelete(old_dir, old_name, isdir);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        errCode = new_node ? FS.mayDelete(new_dir, new_name, isdir) : FS.mayCreate(new_dir, new_name);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        if (!old_dir.node_ops.rename) {
          throw new FS.ErrnoError(63)
        }
        if (FS.isMountpoint(old_node) || new_node && FS.isMountpoint(new_node)) {
          throw new FS.ErrnoError(10)
        }
        if (new_dir !== old_dir) {
          errCode = FS.nodePermissions(old_dir, "w");
          if (errCode) {
            throw new FS.ErrnoError(errCode)
          }
        }
        FS.hashRemoveNode(old_node);
        try {
          old_dir.node_ops.rename(old_node, new_dir, new_name);
          old_node.parent = new_dir
        } catch (e) {
          throw e
        } finally {
          FS.hashAddNode(old_node)
        }
      },
      rmdir(path) {
        var lookup = FS.lookupPath(path, {
          parent: true
        });
        var parent = lookup.node;
        var name = PATH.basename(path);
        var node = FS.lookupNode(parent, name);
        var errCode = FS.mayDelete(parent, name, true);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        if (!parent.node_ops.rmdir) {
          throw new FS.ErrnoError(63)
        }
        if (FS.isMountpoint(node)) {
          throw new FS.ErrnoError(10)
        }
        parent.node_ops.rmdir(parent, name);
        FS.destroyNode(node)
      },
      readdir(path) {
        var lookup = FS.lookupPath(path, {
          follow: true
        });
        var node = lookup.node;
        var readdir = FS.checkOpExists(node.node_ops.readdir, 54);
        return readdir(node)
      },
      unlink(path) {
        var lookup = FS.lookupPath(path, {
          parent: true
        });
        var parent = lookup.node;
        if (!parent) {
          throw new FS.ErrnoError(44)
        }
        var name = PATH.basename(path);
        var node = FS.lookupNode(parent, name);
        var errCode = FS.mayDelete(parent, name, false);
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        if (!parent.node_ops.unlink) {
          throw new FS.ErrnoError(63)
        }
        if (FS.isMountpoint(node)) {
          throw new FS.ErrnoError(10)
        }
        parent.node_ops.unlink(parent, name);
        FS.destroyNode(node)
      },
      readlink(path) {
        var lookup = FS.lookupPath(path);
        var link = lookup.node;
        if (!link) {
          throw new FS.ErrnoError(44)
        }
        if (!link.node_ops.readlink) {
          throw new FS.ErrnoError(28)
        }
        return link.node_ops.readlink(link)
      },
      stat(path, dontFollow) {
        var lookup = FS.lookupPath(path, {
          follow: !dontFollow
        });
        var node = lookup.node;
        var getattr = FS.checkOpExists(node.node_ops.getattr, 63);
        return getattr(node)
      },
      fstat(fd) {
        var stream = FS.getStreamChecked(fd);
        var node = stream.node;
        var getattr = stream.stream_ops.getattr;
        var arg = getattr ? stream : node;
        getattr ??= node.node_ops.getattr;
        FS.checkOpExists(getattr, 63);
        return getattr(arg)
      },
      lstat(path) {
        return FS.stat(path, true)
      },
      doChmod(stream, node, mode, dontFollow) {
        FS.doSetAttr(stream, node, {
          mode: mode & 4095 | node.mode & ~4095,
          ctime: Date.now(),
          dontFollow
        })
      },
      chmod(path, mode, dontFollow) {
        var node;
        if (typeof path == "string") {
          var lookup = FS.lookupPath(path, {
            follow: !dontFollow
          });
          node = lookup.node
        } else {
          node = path
        }
        FS.doChmod(null, node, mode, dontFollow)
      },
      lchmod(path, mode) {
        FS.chmod(path, mode, true)
      },
      fchmod(fd, mode) {
        var stream = FS.getStreamChecked(fd);
        FS.doChmod(stream, stream.node, mode, false)
      },
      doChown(stream, node, dontFollow) {
        FS.doSetAttr(stream, node, {
          timestamp: Date.now(),
          dontFollow
        })
      },
      chown(path, uid, gid, dontFollow) {
        var node;
        if (typeof path == "string") {
          var lookup = FS.lookupPath(path, {
            follow: !dontFollow
          });
          node = lookup.node
        } else {
          node = path
        }
        FS.doChown(null, node, dontFollow)
      },
      lchown(path, uid, gid) {
        FS.chown(path, uid, gid, true)
      },
      fchown(fd, uid, gid) {
        var stream = FS.getStreamChecked(fd);
        FS.doChown(stream, stream.node, false)
      },
      doTruncate(stream, node, len) {
        if (FS.isDir(node.mode)) {
          throw new FS.ErrnoError(31)
        }
        if (!FS.isFile(node.mode)) {
          throw new FS.ErrnoError(28)
        }
        var errCode = FS.nodePermissions(node, "w");
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        FS.doSetAttr(stream, node, {
          size: len,
          timestamp: Date.now()
        })
      },
      truncate(path, len) {
        if (len < 0) {
          throw new FS.ErrnoError(28)
        }
        var node;
        if (typeof path == "string") {
          var lookup = FS.lookupPath(path, {
            follow: true
          });
          node = lookup.node
        } else {
          node = path
        }
        FS.doTruncate(null, node, len)
      },
      ftruncate(fd, len) {
        var stream = FS.getStreamChecked(fd);
        if (len < 0 || (stream.flags & 2097155) === 0) {
          throw new FS.ErrnoError(28)
        }
        FS.doTruncate(stream, stream.node, len)
      },
      utime(path, atime, mtime) {
        var lookup = FS.lookupPath(path, {
          follow: true
        });
        var node = lookup.node;
        var setattr = FS.checkOpExists(node.node_ops.setattr, 63);
        setattr(node, {
          atime,
          mtime
        })
      },
      open(path, flags, mode = 438) {
        if (path === "") {
          throw new FS.ErrnoError(44)
        }
        flags = typeof flags == "string" ? FS_modeStringToFlags(flags) : flags;
        if (flags & 64) {
          mode = mode & 4095 | 32768
        } else {
          mode = 0
        }
        var node;
        var isDirPath;
        if (typeof path == "object") {
          node = path
        } else {
          isDirPath = path.endsWith("/");
          var lookup = FS.lookupPath(path, {
            follow: !(flags & 131072),
            noent_okay: true
          });
          node = lookup.node;
          path = lookup.path
        }
        var created = false;
        if (flags & 64) {
          if (node) {
            if (flags & 128) {
              throw new FS.ErrnoError(20)
            }
          } else if (isDirPath) {
            throw new FS.ErrnoError(31)
          } else {
            node = FS.mknod(path, mode | 511, 0);
            created = true
          }
        }
        if (!node) {
          throw new FS.ErrnoError(44)
        }
        if (FS.isChrdev(node.mode)) {
          flags &= ~512
        }
        if (flags & 65536 && !FS.isDir(node.mode)) {
          throw new FS.ErrnoError(54)
        }
        if (!created) {
          var errCode = FS.mayOpen(node, flags);
          if (errCode) {
            throw new FS.ErrnoError(errCode)
          }
        }
        if (flags & 512 && !created) {
          FS.truncate(node, 0)
        }
        flags &= ~(128 | 512 | 131072);
        var stream = FS.createStream({
          node,
          path: FS.getPath(node),
          flags,
          seekable: true,
          position: 0,
          stream_ops: node.stream_ops,
          ungotten: [],
          error: false
        });
        if (stream.stream_ops.open) {
          stream.stream_ops.open(stream)
        }
        if (created) {
          FS.chmod(node, mode & 511)
        }
        if (Module["logReadFiles"] && !(flags & 1)) {
          if (!(path in FS.readFiles)) {
            FS.readFiles[path] = 1
          }
        }
        return stream
      },
      close(stream) {
        if (FS.isClosed(stream)) {
          throw new FS.ErrnoError(8)
        }
        if (stream.getdents) stream.getdents = null;
        try {
          if (stream.stream_ops.close) {
            stream.stream_ops.close(stream)
          }
        } catch (e) {
          throw e
        } finally {
          FS.closeStream(stream.fd)
        }
        stream.fd = null
      },
      isClosed(stream) {
        return stream.fd === null
      },
      llseek(stream, offset, whence) {
        if (FS.isClosed(stream)) {
          throw new FS.ErrnoError(8)
        }
        if (!stream.seekable || !stream.stream_ops.llseek) {
          throw new FS.ErrnoError(70)
        }
        if (whence != 0 && whence != 1 && whence != 2) {
          throw new FS.ErrnoError(28)
        }
        stream.position = stream.stream_ops.llseek(stream, offset, whence);
        stream.ungotten = [];
        return stream.position
      },
      read(stream, buffer, offset, length, position) {
        if (length < 0 || position < 0) {
          throw new FS.ErrnoError(28)
        }
        if (FS.isClosed(stream)) {
          throw new FS.ErrnoError(8)
        }
        if ((stream.flags & 2097155) === 1) {
          throw new FS.ErrnoError(8)
        }
        if (FS.isDir(stream.node.mode)) {
          throw new FS.ErrnoError(31)
        }
        if (!stream.stream_ops.read) {
          throw new FS.ErrnoError(28)
        }
        var seeking = typeof position != "undefined";
        if (!seeking) {
          position = stream.position
        } else if (!stream.seekable) {
          throw new FS.ErrnoError(70)
        }
        var bytesRead = stream.stream_ops.read(stream, buffer, offset, length, position);
        if (!seeking) stream.position += bytesRead;
        return bytesRead
      },
      write(stream, buffer, offset, length, position, canOwn) {
        if (length < 0 || position < 0) {
          throw new FS.ErrnoError(28)
        }
        if (FS.isClosed(stream)) {
          throw new FS.ErrnoError(8)
        }
        if ((stream.flags & 2097155) === 0) {
          throw new FS.ErrnoError(8)
        }
        if (FS.isDir(stream.node.mode)) {
          throw new FS.ErrnoError(31)
        }
        if (!stream.stream_ops.write) {
          throw new FS.ErrnoError(28)
        }
        if (stream.seekable && stream.flags & 1024) {
          FS.llseek(stream, 0, 2)
        }
        var seeking = typeof position != "undefined";
        if (!seeking) {
          position = stream.position
        } else if (!stream.seekable) {
          throw new FS.ErrnoError(70)
        }
        var bytesWritten = stream.stream_ops.write(stream, buffer, offset, length, position, canOwn);
        if (!seeking) stream.position += bytesWritten;
        return bytesWritten
      },
      mmap(stream, length, position, prot, flags) {
        if ((prot & 2) !== 0 && (flags & 2) === 0 && (stream.flags & 2097155) !== 2) {
          throw new FS.ErrnoError(2)
        }
        if ((stream.flags & 2097155) === 1) {
          throw new FS.ErrnoError(2)
        }
        if (!stream.stream_ops.mmap) {
          throw new FS.ErrnoError(43)
        }
        if (!length) {
          throw new FS.ErrnoError(28)
        }
        return stream.stream_ops.mmap(stream, length, position, prot, flags)
      },
      msync(stream, buffer, offset, length, mmapFlags) {
        if (!stream.stream_ops.msync) {
          return 0
        }
        return stream.stream_ops.msync(stream, buffer, offset, length, mmapFlags)
      },
      ioctl(stream, cmd, arg) {
        if (!stream.stream_ops.ioctl) {
          throw new FS.ErrnoError(59)
        }
        return stream.stream_ops.ioctl(stream, cmd, arg)
      },
      readFile(path, opts = {}) {
        opts.flags = opts.flags || 0;
        opts.encoding = opts.encoding || "binary";
        if (opts.encoding !== "utf8" && opts.encoding !== "binary") {
          throw new Error(`Invalid encoding type "${opts.encoding}"`)
        }
        var ret;
        var stream = FS.open(path, opts.flags);
        var stat = FS.stat(path);
        var length = stat.size;
        var buf = new Uint8Array(length);
        FS.read(stream, buf, 0, length, 0);
        if (opts.encoding === "utf8") {
          ret = UTF8ArrayToString(buf)
        } else if (opts.encoding === "binary") {
          ret = buf
        }
        FS.close(stream);
        return ret
      },
      writeFile(path, data, opts = {}) {
        opts.flags = opts.flags || 577;
        var stream = FS.open(path, opts.flags, opts.mode);
        if (typeof data == "string") {
          var buf = new Uint8Array(lengthBytesUTF8(data) + 1);
          var actualNumBytes = stringToUTF8Array(data, buf, 0, buf.length);
          FS.write(stream, buf, 0, actualNumBytes, undefined, opts.canOwn)
        } else if (ArrayBuffer.isView(data)) {
          FS.write(stream, data, 0, data.byteLength, undefined, opts.canOwn)
        } else {
          throw new Error("Unsupported data type")
        }
        FS.close(stream)
      },
      cwd: () => FS.currentPath,
      chdir(path) {
        var lookup = FS.lookupPath(path, {
          follow: true
        });
        if (lookup.node === null) {
          throw new FS.ErrnoError(44)
        }
        if (!FS.isDir(lookup.node.mode)) {
          throw new FS.ErrnoError(54)
        }
        var errCode = FS.nodePermissions(lookup.node, "x");
        if (errCode) {
          throw new FS.ErrnoError(errCode)
        }
        FS.currentPath = lookup.path
      },
      createDefaultDirectories() {
        FS.mkdir("/tmp");
        FS.mkdir("/home");
        FS.mkdir("/home/web_user")
      },
      createDefaultDevices() {
        FS.mkdir("/dev");
        FS.registerDevice(FS.makedev(1, 3), {
          read: () => 0,
          write: (stream, buffer, offset, length, pos) => length,
          llseek: () => 0
        });
        FS.mkdev("/dev/null", FS.makedev(1, 3));
        TTY.register(FS.makedev(5, 0), TTY.default_tty_ops);
        TTY.register(FS.makedev(6, 0), TTY.default_tty1_ops);
        FS.mkdev("/dev/tty", FS.makedev(5, 0));
        FS.mkdev("/dev/tty1", FS.makedev(6, 0));
        var randomBuffer = new Uint8Array(1024),
          randomLeft = 0;
        var randomByte = () => {
          if (randomLeft === 0) {
            randomFill(randomBuffer);
            randomLeft = randomBuffer.byteLength
          }
          return randomBuffer[--randomLeft]
        };
        FS.createDevice("/dev", "random", randomByte);
        FS.createDevice("/dev", "urandom", randomByte);
        FS.mkdir("/dev/shm");
        FS.mkdir("/dev/shm/tmp")
      },
      createSpecialDirectories() {
        FS.mkdir("/proc");
        var proc_self = FS.mkdir("/proc/self");
        FS.mkdir("/proc/self/fd");
        FS.mount({
          mount() {
            var node = FS.createNode(proc_self, "fd", 16895, 73);
            node.stream_ops = {
              llseek: MEMFS.stream_ops.llseek
            };
            node.node_ops = {
              lookup(parent, name) {
                var fd = +name;
                var stream = FS.getStreamChecked(fd);
                var ret = {
                  parent: null,
                  mount: {
                    mountpoint: "fake"
                  },
                  node_ops: {
                    readlink: () => stream.path
                  },
                  id: fd + 1
                };
                ret.parent = ret;
                return ret
              },
              readdir() {
                return Array.from(FS.streams.entries()).filter(([k, v]) => v).map(([k, v]) => k.toString())
              }
            };
            return node
          }
        }, {}, "/proc/self/fd")
      },
      createStandardStreams(input, output, error) {
        if (input) {
          FS.createDevice("/dev", "stdin", input)
        } else {
          FS.symlink("/dev/tty", "/dev/stdin")
        }
        if (output) {
          FS.createDevice("/dev", "stdout", null, output)
        } else {
          FS.symlink("/dev/tty", "/dev/stdout")
        }
        if (error) {
          FS.createDevice("/dev", "stderr", null, error)
        } else {
          FS.symlink("/dev/tty1", "/dev/stderr")
        }
        var stdin = FS.open("/dev/stdin", 0);
        var stdout = FS.open("/dev/stdout", 1);
        var stderr = FS.open("/dev/stderr", 1)
      },
      staticInit() {
        FS.nameTable = new Array(4096);
        FS.mount(MEMFS, {}, "/");
        FS.createDefaultDirectories();
        FS.createDefaultDevices();
        FS.createSpecialDirectories();
        FS.filesystems = {
          MEMFS
        }
      },
      init(input, output, error) {
        FS.initialized = true;
        input ??= Module["stdin"];
        output ??= Module["stdout"];
        error ??= Module["stderr"];
        FS.createStandardStreams(input, output, error)
      },
      quit() {
        FS.initialized = false;
        for (var stream of FS.streams) {
          if (stream) {
            FS.close(stream)
          }
        }
      },
      findObject(path, dontResolveLastLink) {
        var ret = FS.analyzePath(path, dontResolveLastLink);
        if (!ret.exists) {
          return null
        }
        return ret.object
      },
      analyzePath(path, dontResolveLastLink) {
        try {
          var lookup = FS.lookupPath(path, {
            follow: !dontResolveLastLink
          });
          path = lookup.path
        } catch (e) { }
        var ret = {
          isRoot: false,
          exists: false,
          error: 0,
          name: null,
          path: null,
          object: null,
          parentExists: false,
          parentPath: null,
          parentObject: null
        };
        try {
          var lookup = FS.lookupPath(path, {
            parent: true
          });
          ret.parentExists = true;
          ret.parentPath = lookup.path;
          ret.parentObject = lookup.node;
          ret.name = PATH.basename(path);
          lookup = FS.lookupPath(path, {
            follow: !dontResolveLastLink
          });
          ret.exists = true;
          ret.path = lookup.path;
          ret.object = lookup.node;
          ret.name = lookup.node.name;
          ret.isRoot = lookup.path === "/"
        } catch (e) {
          ret.error = e.errno
        }
        return ret
      },
      createPath(parent, path, canRead, canWrite) {
        parent = typeof parent == "string" ? parent : FS.getPath(parent);
        var parts = path.split("/").reverse();
        while (parts.length) {
          var part = parts.pop();
          if (!part) continue;
          var current = PATH.join2(parent, part);
          try {
            FS.mkdir(current)
          } catch (e) {
            if (e.errno != 20) throw e
          }
          parent = current
        }
        return current
      },
      createFile(parent, name, properties, canRead, canWrite) {
        var path = PATH.join2(typeof parent == "string" ? parent : FS.getPath(parent), name);
        var mode = FS_getMode(canRead, canWrite);
        return FS.create(path, mode)
      },
      createDataFile(parent, name, data, canRead, canWrite, canOwn) {
        var path = name;
        if (parent) {
          parent = typeof parent == "string" ? parent : FS.getPath(parent);
          path = name ? PATH.join2(parent, name) : parent
        }
        var mode = FS_getMode(canRead, canWrite);
        var node = FS.create(path, mode);
        if (data) {
          if (typeof data == "string") {
            var arr = new Array(data.length);
            for (var i = 0, len = data.length; i < len; ++i) arr[i] = data.charCodeAt(i);
            data = arr
          }
          FS.chmod(node, mode | 146);
          var stream = FS.open(node, 577);
          FS.write(stream, data, 0, data.length, 0, canOwn);
          FS.close(stream);
          FS.chmod(node, mode)
        }
      },
      createDevice(parent, name, input, output) {
        var path = PATH.join2(typeof parent == "string" ? parent : FS.getPath(parent), name);
        var mode = FS_getMode(!!input, !!output);
        FS.createDevice.major ??= 64;
        var dev = FS.makedev(FS.createDevice.major++, 0);
        FS.registerDevice(dev, {
          open(stream) {
            stream.seekable = false
          },
          close(stream) {
            if (output?.buffer?.length) {
              output(10)
            }
          },
          read(stream, buffer, offset, length, pos) {
            var bytesRead = 0;
            for (var i = 0; i < length; i++) {
              var result;
              try {
                result = input()
              } catch (e) {
                throw new FS.ErrnoError(29)
              }
              if (result === undefined && bytesRead === 0) {
                throw new FS.ErrnoError(6)
              }
              if (result === null || result === undefined) break;
              bytesRead++;
              buffer[offset + i] = result
            }
            if (bytesRead) {
              stream.node.atime = Date.now()
            }
            return bytesRead
          },
          write(stream, buffer, offset, length, pos) {
            for (var i = 0; i < length; i++) {
              try {
                output(buffer[offset + i])
              } catch (e) {
                throw new FS.ErrnoError(29)
              }
            }
            if (length) {
              stream.node.mtime = stream.node.ctime = Date.now()
            }
            return i
          }
        });
        return FS.mkdev(path, mode, dev)
      },
      forceLoadFile(obj) {
        if (obj.isDevice || obj.isFolder || obj.link || obj.contents) return true;
        if (typeof XMLHttpRequest != "undefined") {
          throw new Error("Lazy loading should have been performed (contents set) in createLazyFile, but it was not. Lazy loading only works in web workers. Use --embed-file or --preload-file in emcc on the main thread.")
        } else {
          try {
            obj.contents = readBinary(obj.url);
            obj.usedBytes = obj.contents.length
          } catch (e) {
            throw new FS.ErrnoError(29)
          }
        }
      },
      createLazyFile(parent, name, url, canRead, canWrite) {
        class LazyUint8Array {
          lengthKnown = false;
          chunks = [];
          get(idx) {
            if (idx > this.length - 1 || idx < 0) {
              return undefined
            }
            var chunkOffset = idx % this.chunkSize;
            var chunkNum = idx / this.chunkSize | 0;
            return this.getter(chunkNum)[chunkOffset]
          }
          setDataGetter(getter) {
            this.getter = getter
          }
          cacheLength() {
            var xhr = new XMLHttpRequest;
            xhr.open("HEAD", url, false);
            xhr.send(null);
            if (!(xhr.status >= 200 && xhr.status < 300 || xhr.status === 304)) throw new Error("Couldn't load " + url + ". Status: " + xhr.status);
            var datalength = Number(xhr.getResponseHeader("Content-length"));
            var header;
            var hasByteServing = (header = xhr.getResponseHeader("Accept-Ranges")) && header === "bytes";
            var usesGzip = (header = xhr.getResponseHeader("Content-Encoding")) && header === "gzip";
            var chunkSize = 1024 * 1024;
            if (!hasByteServing) chunkSize = datalength;
            var doXHR = (from, to) => {
              if (from > to) throw new Error("invalid range (" + from + ", " + to + ") or no bytes requested!");
              if (to > datalength - 1) throw new Error("only " + datalength + " bytes available! programmer error!");
              var xhr = new XMLHttpRequest;
              xhr.open("GET", url, false);
              if (datalength !== chunkSize) xhr.setRequestHeader("Range", "bytes=" + from + "-" + to);
              xhr.responseType = "arraybuffer";
              if (xhr.overrideMimeType) {
                xhr.overrideMimeType("text/plain; charset=x-user-defined")
              }
              xhr.send(null);
              if (!(xhr.status >= 200 && xhr.status < 300 || xhr.status === 304)) throw new Error("Couldn't load " + url + ". Status: " + xhr.status);
              if (xhr.response !== undefined) {
                return new Uint8Array(xhr.response || [])
              }
              return intArrayFromString(xhr.responseText || "", true)
            };
            var lazyArray = this;
            lazyArray.setDataGetter(chunkNum => {
              var start = chunkNum * chunkSize;
              var end = (chunkNum + 1) * chunkSize - 1;
              end = Math.min(end, datalength - 1);
              if (typeof lazyArray.chunks[chunkNum] == "undefined") {
                lazyArray.chunks[chunkNum] = doXHR(start, end)
              }
              if (typeof lazyArray.chunks[chunkNum] == "undefined") throw new Error("doXHR failed!");
              return lazyArray.chunks[chunkNum]
            });
            if (usesGzip || !datalength) {
              chunkSize = datalength = 1;
              datalength = this.getter(0).length;
              chunkSize = datalength;
              out("LazyFiles on gzip forces download of the whole file when length is accessed")
            }
            this._length = datalength;
            this._chunkSize = chunkSize;
            this.lengthKnown = true
          }
          get length() {
            if (!this.lengthKnown) {
              this.cacheLength()
            }
            return this._length
          }
          get chunkSize() {
            if (!this.lengthKnown) {
              this.cacheLength()
            }
            return this._chunkSize
          }
        }
        if (typeof XMLHttpRequest != "undefined") {
          if (!ENVIRONMENT_IS_WORKER) throw "Cannot do synchronous binary XHRs outside webworkers in modern browsers. Use --embed-file or --preload-file in emcc";
          var lazyArray = new LazyUint8Array;
          var properties = {
            isDevice: false,
            contents: lazyArray
          }
        } else {
          var properties = {
            isDevice: false,
            url
          }
        }
        var node = FS.createFile(parent, name, properties, canRead, canWrite);
        if (properties.contents) {
          node.contents = properties.contents
        } else if (properties.url) {
          node.contents = null;
          node.url = properties.url
        }
        Object.defineProperties(node, {
          usedBytes: {
            get: function () {
              return this.contents.length
            }
          }
        });
        var stream_ops = {};
        var keys = Object.keys(node.stream_ops);
        keys.forEach(key => {
          var fn = node.stream_ops[key];
          stream_ops[key] = (...args) => {
            FS.forceLoadFile(node);
            return fn(...args)
          }
        });

        function writeChunks(stream, buffer, offset, length, position) {
          var contents = stream.node.contents;
          if (position >= contents.length) return 0;
          var size = Math.min(contents.length - position, length);
          if (contents.slice) {
            for (var i = 0; i < size; i++) {
              buffer[offset + i] = contents[position + i]
            }
          } else {
            for (var i = 0; i < size; i++) {
              buffer[offset + i] = contents.get(position + i)
            }
          }
          return size
        }
        stream_ops.read = (stream, buffer, offset, length, position) => {
          FS.forceLoadFile(node);
          return writeChunks(stream, buffer, offset, length, position)
        };
        stream_ops.mmap = (stream, length, position, prot, flags) => {
          FS.forceLoadFile(node);
          var ptr = mmapAlloc(length);
          if (!ptr) {
            throw new FS.ErrnoError(48)
          }
          writeChunks(stream, (growMemViews(), HEAP8), ptr, length, position);
          return {
            ptr,
            allocated: true
          }
        };
        node.stream_ops = stream_ops;
        return node
      }
    };
    var SYSCALLS = {
      DEFAULT_POLLMASK: 5,
      calculateAt(dirfd, path, allowEmpty) {
        if (PATH.isAbs(path)) {
          return path
        }
        var dir;
        if (dirfd === -100) {
          dir = FS.cwd()
        } else {
          var dirstream = SYSCALLS.getStreamFromFD(dirfd);
          dir = dirstream.path
        }
        if (path.length == 0) {
          if (!allowEmpty) {
            throw new FS.ErrnoError(44)
          }
          return dir
        }
        return dir + "/" + path
      },
      writeStat(buf, stat) {
        (growMemViews(), HEAP32)[buf >> 2] = stat.dev;
        (growMemViews(), HEAP32)[buf + 4 >> 2] = stat.mode;
        (growMemViews(), HEAPU32)[buf + 8 >> 2] = stat.nlink;
        (growMemViews(), HEAP32)[buf + 12 >> 2] = stat.uid;
        (growMemViews(), HEAP32)[buf + 16 >> 2] = stat.gid;
        (growMemViews(), HEAP32)[buf + 20 >> 2] = stat.rdev;
        (growMemViews(), HEAP64)[buf + 24 >> 3] = BigInt(stat.size);
        (growMemViews(), HEAP32)[buf + 32 >> 2] = 4096;
        (growMemViews(), HEAP32)[buf + 36 >> 2] = stat.blocks;
        var atime = stat.atime.getTime();
        var mtime = stat.mtime.getTime();
        var ctime = stat.ctime.getTime();
        (growMemViews(), HEAP64)[buf + 40 >> 3] = BigInt(Math.floor(atime / 1e3));
        (growMemViews(), HEAPU32)[buf + 48 >> 2] = atime % 1e3 * 1e3 * 1e3;
        (growMemViews(), HEAP64)[buf + 56 >> 3] = BigInt(Math.floor(mtime / 1e3));
        (growMemViews(), HEAPU32)[buf + 64 >> 2] = mtime % 1e3 * 1e3 * 1e3;
        (growMemViews(), HEAP64)[buf + 72 >> 3] = BigInt(Math.floor(ctime / 1e3));
        (growMemViews(), HEAPU32)[buf + 80 >> 2] = ctime % 1e3 * 1e3 * 1e3;
        (growMemViews(), HEAP64)[buf + 88 >> 3] = BigInt(stat.ino);
        return 0
      },
      writeStatFs(buf, stats) {
        (growMemViews(), HEAP32)[buf + 4 >> 2] = stats.bsize;
        (growMemViews(), HEAP32)[buf + 40 >> 2] = stats.bsize;
        (growMemViews(), HEAP32)[buf + 8 >> 2] = stats.blocks;
        (growMemViews(), HEAP32)[buf + 12 >> 2] = stats.bfree;
        (growMemViews(), HEAP32)[buf + 16 >> 2] = stats.bavail;
        (growMemViews(), HEAP32)[buf + 20 >> 2] = stats.files;
        (growMemViews(), HEAP32)[buf + 24 >> 2] = stats.ffree;
        (growMemViews(), HEAP32)[buf + 28 >> 2] = stats.fsid;
        (growMemViews(), HEAP32)[buf + 44 >> 2] = stats.flags;
        (growMemViews(), HEAP32)[buf + 36 >> 2] = stats.namelen
      },
      doMsync(addr, stream, len, flags, offset) {
        if (!FS.isFile(stream.node.mode)) {
          throw new FS.ErrnoError(43)
        }
        if (flags & 2) {
          return 0
        }
        var buffer = (growMemViews(), HEAPU8).slice(addr, addr + len);
        FS.msync(stream, buffer, offset, len, flags)
      },
      getStreamFromFD(fd) {
        var stream = FS.getStreamChecked(fd);
        return stream
      },
      varargs: undefined,
      getStr(ptr) {
        var ret = UTF8ToString(ptr);
        return ret
      }
    };

    function ___syscall_chdir(path) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(3, 0, 1, path);
      try {
        path = SYSCALLS.getStr(path);
        FS.chdir(path);
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_dup(fd) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(4, 0, 1, fd);
      try {
        var old = SYSCALLS.getStreamFromFD(fd);
        return FS.dupStream(old).fd
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_dup3(fd, newfd, flags) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(5, 0, 1, fd, newfd, flags);
      try {
        var old = SYSCALLS.getStreamFromFD(fd);
        if (old.fd === newfd) return -28;
        if (newfd < 0 || newfd >= FS.MAX_OPEN_FDS) return -8;
        var existing = FS.getStream(newfd);
        if (existing) FS.close(existing);
        return FS.dupStream(old, newfd).fd
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_faccessat(dirfd, path, amode, flags) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(6, 0, 1, dirfd, path, amode, flags);
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        if (amode & ~7) {
          return -28
        }
        var lookup = FS.lookupPath(path, {
          follow: true
        });
        var node = lookup.node;
        if (!node) {
          return -44
        }
        var perms = "";
        if (amode & 4) perms += "r";
        if (amode & 2) perms += "w";
        if (amode & 1) perms += "x";
        if (perms && FS.nodePermissions(node, perms)) {
          return -2
        }
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var syscallGetVarargI = () => {
      var ret = (growMemViews(), HEAP32)[+SYSCALLS.varargs >> 2];
      SYSCALLS.varargs += 4;
      return ret
    };
    var syscallGetVarargP = syscallGetVarargI;

    function ___syscall_fcntl64(fd, cmd, varargs) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(7, 0, 1, fd, cmd, varargs);
      SYSCALLS.varargs = varargs;
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        switch (cmd) {
          case 0: {
            var arg = syscallGetVarargI();
            if (arg < 0) {
              return -28
            }
            while (FS.streams[arg]) {
              arg++
            }
            var newStream;
            newStream = FS.dupStream(stream, arg);
            return newStream.fd
          }
          case 1:
          case 2:
            return 0;
          case 3:
            return stream.flags;
          case 4: {
            var arg = syscallGetVarargI();
            stream.flags |= arg;
            return 0
          }
          case 12: {
            var arg = syscallGetVarargP();
            var offset = 0;
            (growMemViews(), HEAP16)[arg + offset >> 1] = 2;
            return 0
          }
          case 13:
          case 14:
            return 0
        }
        return -28
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_fstat64(fd, buf) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(8, 0, 1, fd, buf);
      try {
        return SYSCALLS.writeStat(buf, FS.fstat(fd))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var INT53_MAX = 9007199254740992;
    var INT53_MIN = -9007199254740992;
    var bigintToI53Checked = num => num < INT53_MIN || num > INT53_MAX ? NaN : Number(num);

    function ___syscall_ftruncate64(fd, length) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(9, 0, 1, fd, length);
      length = bigintToI53Checked(length);
      try {
        if (isNaN(length)) return -61;
        FS.ftruncate(fd, length);
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var stringToUTF8 = (str, outPtr, maxBytesToWrite) => stringToUTF8Array(str, (growMemViews(), HEAPU8), outPtr, maxBytesToWrite);

    function ___syscall_getcwd(buf, size) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(10, 0, 1, buf, size);
      try {
        if (size === 0) return -28;
        var cwd = FS.cwd();
        var cwdLengthInBytes = lengthBytesUTF8(cwd) + 1;
        if (size < cwdLengthInBytes) return -68;
        stringToUTF8(cwd, buf, size);
        return cwdLengthInBytes
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_getdents64(fd, dirp, count) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(11, 0, 1, fd, dirp, count);
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        stream.getdents ||= FS.readdir(stream.path);
        var struct_size = 280;
        var pos = 0;
        var off = FS.llseek(stream, 0, 1);
        var startIdx = Math.floor(off / struct_size);
        var endIdx = Math.min(stream.getdents.length, startIdx + Math.floor(count / struct_size));
        for (var idx = startIdx; idx < endIdx; idx++) {
          var id;
          var type;
          var name = stream.getdents[idx];
          if (name === ".") {
            id = stream.node.id;
            type = 4
          } else if (name === "..") {
            var lookup = FS.lookupPath(stream.path, {
              parent: true
            });
            id = lookup.node.id;
            type = 4
          } else {
            var child;
            try {
              child = FS.lookupNode(stream.node, name)
            } catch (e) {
              if (e?.errno === 28) {
                continue
              }
              throw e
            }
            id = child.id;
            type = FS.isChrdev(child.mode) ? 2 : FS.isDir(child.mode) ? 4 : FS.isLink(child.mode) ? 10 : 8
          } (growMemViews(), HEAP64)[dirp + pos >> 3] = BigInt(id);
          (growMemViews(), HEAP64)[dirp + pos + 8 >> 3] = BigInt((idx + 1) * struct_size);
          (growMemViews(), HEAP16)[dirp + pos + 16 >> 1] = 280;
          (growMemViews(), HEAP8)[dirp + pos + 18] = type;
          stringToUTF8(name, dirp + pos + 19, 256);
          pos += struct_size
        }
        FS.llseek(stream, idx * struct_size, 0);
        return pos
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_ioctl(fd, op, varargs) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(12, 0, 1, fd, op, varargs);
      SYSCALLS.varargs = varargs;
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        switch (op) {
          case 21509: {
            if (!stream.tty) return -59;
            return 0
          }
          case 21505: {
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tcgets) {
              var termios = stream.tty.ops.ioctl_tcgets(stream);
              var argp = syscallGetVarargP();
              (growMemViews(), HEAP32)[argp >> 2] = termios.c_iflag || 0;
              (growMemViews(), HEAP32)[argp + 4 >> 2] = termios.c_oflag || 0;
              (growMemViews(), HEAP32)[argp + 8 >> 2] = termios.c_cflag || 0;
              (growMemViews(), HEAP32)[argp + 12 >> 2] = termios.c_lflag || 0;
              for (var i = 0; i < 32; i++) {
                (growMemViews(), HEAP8)[argp + i + 17] = termios.c_cc[i] || 0
              }
              return 0
            }
            return 0
          }
          case 21510:
          case 21511:
          case 21512: {
            if (!stream.tty) return -59;
            return 0
          }
          case 21506:
          case 21507:
          case 21508: {
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tcsets) {
              var argp = syscallGetVarargP();
              var c_iflag = (growMemViews(), HEAP32)[argp >> 2];
              var c_oflag = (growMemViews(), HEAP32)[argp + 4 >> 2];
              var c_cflag = (growMemViews(), HEAP32)[argp + 8 >> 2];
              var c_lflag = (growMemViews(), HEAP32)[argp + 12 >> 2];
              var c_cc = [];
              for (var i = 0; i < 32; i++) {
                c_cc.push((growMemViews(), HEAP8)[argp + i + 17])
              }
              return stream.tty.ops.ioctl_tcsets(stream.tty, op, {
                c_iflag,
                c_oflag,
                c_cflag,
                c_lflag,
                c_cc
              })
            }
            return 0
          }
          case 21519: {
            if (!stream.tty) return -59;
            var argp = syscallGetVarargP();
            (growMemViews(), HEAP32)[argp >> 2] = 0;
            return 0
          }
          case 21520: {
            if (!stream.tty) return -59;
            return -28
          }
          case 21531: {
            var argp = syscallGetVarargP();
            return FS.ioctl(stream, op, argp)
          }
          case 21523: {
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tiocgwinsz) {
              var winsize = stream.tty.ops.ioctl_tiocgwinsz(stream.tty);
              var argp = syscallGetVarargP();
              (growMemViews(), HEAP16)[argp >> 1] = winsize[0];
              (growMemViews(), HEAP16)[argp + 2 >> 1] = winsize[1]
            }
            return 0
          }
          case 21524: {
            if (!stream.tty) return -59;
            return 0
          }
          case 21515: {
            if (!stream.tty) return -59;
            return 0
          }
          default:
            return -28
        }
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_lstat64(path, buf) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(13, 0, 1, path, buf);
      try {
        path = SYSCALLS.getStr(path);
        return SYSCALLS.writeStat(buf, FS.lstat(path))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_mkdirat(dirfd, path, mode) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(14, 0, 1, dirfd, path, mode);
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        FS.mkdir(path, mode, 0);
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_newfstatat(dirfd, path, buf, flags) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(15, 0, 1, dirfd, path, buf, flags);
      try {
        path = SYSCALLS.getStr(path);
        var nofollow = flags & 256;
        var allowEmpty = flags & 4096;
        flags = flags & ~6400;
        path = SYSCALLS.calculateAt(dirfd, path, allowEmpty);
        return SYSCALLS.writeStat(buf, nofollow ? FS.lstat(path) : FS.stat(path))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_openat(dirfd, path, flags, varargs) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(16, 0, 1, dirfd, path, flags, varargs);
      SYSCALLS.varargs = varargs;
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        var mode = varargs ? syscallGetVarargI() : 0;
        return FS.open(path, flags, mode).fd
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function xterm_pty_old_poll(fds, nfds, timeout) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(17, 0, 1, fds, nfds, timeout);
      try {
        var nonzero = 0;
        for (var i = 0; i < nfds; i++) {
          var pollfd = fds + 8 * i;
          var fd = (growMemViews(), HEAP32)[pollfd >> 2];
          var events = (growMemViews(), HEAP16)[pollfd + 4 >> 1];
          var mask = 32;
          var stream = FS.getStream(fd);
          if (stream) {
            mask = SYSCALLS.DEFAULT_POLLMASK;
            if (stream.stream_ops.poll) {
              mask = stream.stream_ops.poll(stream, -1)
            }
          }
          mask &= events | 8 | 16;
          if (mask) nonzero++;
          (growMemViews(), HEAP16)[pollfd + 6 >> 1] = mask
        }
        return nonzero
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var PTY_waitForReadableWithCallback = callback => {
      if (PTY_pollTimeout === 0) {
        return callback(PTY.readable ? 0 : 2)
      }
      let handlerReadable, handlerSignal, timeoutId;
      new Promise(resolve => {
        handlerReadable = PTY.onReadable(() => resolve(0));
        handlerSignal = PTY.onSignal(() => resolve(1));
        if (PTY_pollTimeout >= 0) {
          timeoutId = setTimeout(resolve, PTY_pollTimeout, 2)
        }
      }).then(type => {
        handlerReadable.dispose();
        handlerSignal.dispose();
        clearTimeout(timeoutId);
        callback(type)
      })
    };
    var PTY_waitForReadableWithAtomicImpl = function (atomicIndex) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(18, 0, 0, atomicIndex);
      PTY_waitForReadableWithCallback(type => {
        Atomics.store((growMemViews(), HEAP32), atomicIndex, type);
        Atomics.notify((growMemViews(), HEAP32), atomicIndex)
      })
    };
    var PTY_atomicIndex = 0;
    var PTY_waitForReadableWithAtomic = callback => {
      if (!PTY_atomicIndex) {
        PTY_atomicIndex = _malloc(4) >> 2
      } (growMemViews(), HEAP32)[PTY_atomicIndex] = -1;
      PTY_waitForReadableWithAtomicImpl(PTY_atomicIndex);
      Atomics.wait((growMemViews(), HEAP32), PTY_atomicIndex, -1);
      callback((growMemViews(), HEAP32)[PTY_atomicIndex])
    };
    var PTY_waitForReadable = PTY_waitForReadableWithAtomic;
    var PTY_handleSleepWithAtomic = startAsync => {
      let result;
      startAsync(r => result = r);
      return result
    };
    var PTY_handleSleep = PTY_handleSleepWithAtomic;
    var PTY_wrapPoll = impl => PTY_handleSleep(wakeUp => {
      let result = impl();
      if (result === -1006) {
        PTY_waitForReadable(type => {
          switch (type) {
            case 0:
              wakeUp(impl());
              break;
            case 1:
              wakeUp(-27);
              break;
            case 2:
              wakeUp(0);
              break
          }
        })
      } else {
        wakeUp(result)
      }
    });
    var ___syscall_poll = (fds, nfds, timeout) => PTY_wrapPoll(() => xterm_pty_old_poll(fds, nfds, timeout));

    function ___syscall_readlinkat(dirfd, path, buf, bufsize) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(19, 0, 1, dirfd, path, buf, bufsize);
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        if (bufsize <= 0) return -28;
        var ret = FS.readlink(path);
        var len = Math.min(bufsize, lengthBytesUTF8(ret));
        var endChar = (growMemViews(), HEAP8)[buf + len];
        stringToUTF8(ret, buf, bufsize + 1);
        (growMemViews(), HEAP8)[buf + len] = endChar;
        return len
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_stat64(path, buf) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(20, 0, 1, path, buf);
      try {
        path = SYSCALLS.getStr(path);
        return SYSCALLS.writeStat(buf, FS.stat(path))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_statfs64(path, size, buf) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(21, 0, 1, path, size, buf);
      try {
        SYSCALLS.writeStatFs(buf, FS.statfs(SYSCALLS.getStr(path)));
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_truncate64(path, length) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(22, 0, 1, path, length);
      length = bigintToI53Checked(length);
      try {
        if (isNaN(length)) return -61;
        path = SYSCALLS.getStr(path);
        FS.truncate(path, length);
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_unlinkat(dirfd, path, flags) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(23, 0, 1, dirfd, path, flags);
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        if (!flags) {
          FS.unlink(path)
        } else if (flags === 512) {
          FS.rmdir(path)
        } else {
          return -28
        }
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var readI53FromI64 = ptr => (growMemViews(), HEAPU32)[ptr >> 2] + (growMemViews(), HEAP32)[ptr + 4 >> 2] * 4294967296;

    function ___syscall_utimensat(dirfd, path, times, flags) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(24, 0, 1, dirfd, path, times, flags);
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path, true);
        var now = Date.now(),
          atime, mtime;
        if (!times) {
          atime = now;
          mtime = now
        } else {
          var seconds = readI53FromI64(times);
          var nanoseconds = (growMemViews(), HEAP32)[times + 8 >> 2];
          if (nanoseconds == 1073741823) {
            atime = now
          } else if (nanoseconds == 1073741822) {
            atime = null
          } else {
            atime = seconds * 1e3 + nanoseconds / (1e3 * 1e3)
          }
          times += 16;
          seconds = readI53FromI64(times);
          nanoseconds = (growMemViews(), HEAP32)[times + 8 >> 2];
          if (nanoseconds == 1073741823) {
            mtime = now
          } else if (nanoseconds == 1073741822) {
            mtime = null
          } else {
            mtime = seconds * 1e3 + nanoseconds / (1e3 * 1e3)
          }
        }
        if ((mtime ?? atime) !== null) {
          FS.utime(path, atime, mtime)
        }
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }
    var __abort_js = () => abort("");
    var __emscripten_init_main_thread_js = tb => {
      __emscripten_thread_init(tb, !ENVIRONMENT_IS_WORKER, 1, !ENVIRONMENT_IS_WEB, 65536, false);
      PThread.threadInitTLS()
    };
    var handleException = e => {
      if (e instanceof ExitStatus || e == "unwind") {
        return EXITSTATUS
      }
      quit_(1, e)
    };
    var maybeExit = () => {
      if (!keepRuntimeAlive()) {
        try {
          // if (ENVIRONMENT_IS_PTHREAD) __emscripten_thread_exit(EXITSTATUS);
          // else 
          _exit(EXITSTATUS)
        } catch (e) {
          handleException(e)
        }
      }
    };
    var callUserCallback = func => {
      if (ABORT) {
        return
      }
      try {
        func();
        maybeExit()
      } catch (e) {
        handleException(e)
      }
    };
    var __emscripten_thread_mailbox_await = pthread_ptr => {
      if (typeof Atomics.waitAsync === "function") {
        var wait = Atomics.waitAsync((growMemViews(), HEAP32), pthread_ptr >> 2, pthread_ptr);
        wait.value.then(checkMailbox);
        var waitingAsync = pthread_ptr + 128;
        Atomics.store((growMemViews(), HEAP32), waitingAsync >> 2, 1)
      }
    };
    var checkMailbox = () => {
      var pthread_ptr = _pthread_self();
      if (pthread_ptr) {
        __emscripten_thread_mailbox_await(pthread_ptr);
        callUserCallback(__emscripten_check_mailbox)
      }
    };
    var __emscripten_notify_mailbox_postmessage = (targetThread, currThreadId) => {
      if (targetThread == currThreadId) {
        setTimeout(checkMailbox)
        // } else if (ENVIRONMENT_IS_PTHREAD) {
        //   postMessage({
        //     targetThread,
        //     cmd: "checkMailbox"
        //   })
      } else {
        var worker = PThread.pthreads[targetThread];
        if (!worker) {
          return
        }
        worker.postMessage({
          cmd: "checkMailbox"
        })
      }
    };
    var proxiedJSCallArgs = [];
    var __emscripten_receive_on_main_thread_js = (funcIndex, emAsmAddr, callingThread, numCallArgs, args) => {
      numCallArgs /= 2;
      proxiedJSCallArgs.length = numCallArgs;
      var b = args >> 3;
      for (var i = 0; i < numCallArgs; i++) {
        if ((growMemViews(), HEAP64)[b + 2 * i]) {
          proxiedJSCallArgs[i] = (growMemViews(), HEAP64)[b + 2 * i + 1]
        } else {
          proxiedJSCallArgs[i] = (growMemViews(), HEAPF64)[b + 2 * i + 1]
        }
      }
      var func = proxiedFunctionTable[funcIndex];
      PThread.currentProxiedOperationCallerThread = callingThread;
      var rtn = func(...proxiedJSCallArgs);
      PThread.currentProxiedOperationCallerThread = 0;
      return rtn
    };
    var __emscripten_runtime_keepalive_clear = () => {
      noExitRuntime = false;
      runtimeKeepaliveCounter = 0
    };
    var __emscripten_thread_cleanup = thread => {
      // if (!ENVIRONMENT_IS_PTHREAD) cleanupThread(thread);
      // else 
      postMessage({
        cmd: "cleanupThread",
        thread
      })
    };
    var __emscripten_thread_set_strongref = thread => { };
    var __tzset_js = (timezone, daylight, std_name, dst_name) => {
      var currentYear = (new Date).getFullYear();
      var winter = new Date(currentYear, 0, 1);
      var summer = new Date(currentYear, 6, 1);
      var winterOffset = winter.getTimezoneOffset();
      var summerOffset = summer.getTimezoneOffset();
      var stdTimezoneOffset = Math.max(winterOffset, summerOffset);
      (growMemViews(), HEAPU32)[timezone >> 2] = stdTimezoneOffset * 60;
      (growMemViews(), HEAP32)[daylight >> 2] = Number(winterOffset != summerOffset);
      var extractZone = timezoneOffset => {
        var sign = timezoneOffset >= 0 ? "-" : "+";
        var absOffset = Math.abs(timezoneOffset);
        var hours = String(Math.floor(absOffset / 60)).padStart(2, "0");
        var minutes = String(absOffset % 60).padStart(2, "0");
        return `UTC${sign}${hours}${minutes}`
      };
      var winterName = extractZone(winterOffset);
      var summerName = extractZone(summerOffset);
      if (summerOffset < winterOffset) {
        stringToUTF8(winterName, std_name, 17);
        stringToUTF8(summerName, dst_name, 17)
      } else {
        stringToUTF8(winterName, dst_name, 17);
        stringToUTF8(summerName, std_name, 17)
      }
    };
    var _emscripten_get_now = () => performance.timeOrigin + performance.now();
    var _emscripten_date_now = () => Date.now();
    var nowIsMonotonic = 1;
    var checkWasiClock = clock_id => clock_id >= 0 && clock_id <= 3;

    function _clock_time_get(clk_id, ignored_precision, ptime) {
      ignored_precision = bigintToI53Checked(ignored_precision);
      if (!checkWasiClock(clk_id)) {
        return 28
      }
      var now;
      if (clk_id === 0) {
        now = _emscripten_date_now()
      } else if (nowIsMonotonic) {
        now = _emscripten_get_now()
      } else {
        return 52
      }
      var nsec = Math.round(now * 1e3 * 1e3);
      (growMemViews(), HEAP64)[ptime >> 3] = BigInt(nsec);
      return 0
    }
    var _emscripten_check_blocking_allowed = () => { };
    var _emscripten_exit_with_live_runtime = () => {
      runtimeKeepalivePush();
      throw "unwind"
    };
    var getHeapMax = () => 2147483648;
    var alignMemory = (size, alignment) => Math.ceil(size / alignment) * alignment;
    var growMemory = size => {
      var b = wasmMemory.buffer;
      var pages = (size - b.byteLength + 65535) / 65536 | 0;
      try {
        wasmMemory.grow(pages);
        updateMemoryViews();
        return 1
      } catch (e) { }
    };
    var _emscripten_resize_heap = requestedSize => {
      var oldSize = (growMemViews(), HEAPU8).length;
      requestedSize >>>= 0;
      if (requestedSize <= oldSize) {
        return false
      }
      var maxHeapSize = getHeapMax();
      if (requestedSize > maxHeapSize) {
        return false
      }
      for (var cutDown = 1; cutDown <= 4; cutDown *= 2) {
        var overGrownHeapSize = oldSize * (1 + .2 / cutDown);
        overGrownHeapSize = Math.min(overGrownHeapSize, requestedSize + 100663296);
        var newSize = Math.min(maxHeapSize, alignMemory(Math.max(requestedSize, overGrownHeapSize), 65536));
        var replacement = growMemory(newSize);
        if (replacement) {
          return true
        }
      }
      return false
    };
    var _emscripten_runtime_keepalive_check = keepRuntimeAlive;
    var ENV = {
      TERM: "xterm-256color"
    };
    var getExecutableName = () => thisProgram || "./this.program";
    var getEnvStrings = () => {
      if (!getEnvStrings.strings) {
        var lang = (typeof navigator == "object" && navigator.languages && navigator.languages[0] || "C").replace("-", "_") + ".UTF-8";
        var env = {
          USER: "web_user",
          LOGNAME: "web_user",
          PATH: "/",
          PWD: "/",
          HOME: "/home/web_user",
          LANG: lang,
          _: getExecutableName()
        };
        for (var x in ENV) {
          if (ENV[x] === undefined) delete env[x];
          else env[x] = ENV[x]
        }
        var strings = [];
        for (var x in env) {
          strings.push(`${x}=${env[x]}`)
        }
        getEnvStrings.strings = strings
      }
      return getEnvStrings.strings
    };

    function _environ_get(__environ, environ_buf) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(25, 0, 1, __environ, environ_buf);
      var bufSize = 0;
      var envp = 0;
      for (var string of getEnvStrings()) {
        var ptr = environ_buf + bufSize;
        (growMemViews(), HEAPU32)[__environ + envp >> 2] = ptr;
        bufSize += stringToUTF8(string, ptr, Infinity) + 1;
        envp += 4
      }
      return 0
    }

    function _environ_sizes_get(penviron_count, penviron_buf_size) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(26, 0, 1, penviron_count, penviron_buf_size);
      var strings = getEnvStrings();
      (growMemViews(), HEAPU32)[penviron_count >> 2] = strings.length;
      var bufSize = 0;
      for (var string of strings) {
        bufSize += lengthBytesUTF8(string) + 1
      } (growMemViews(), HEAPU32)[penviron_buf_size >> 2] = bufSize;
      return 0
    }

    function _fd_close(fd) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(27, 0, 1, fd);
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        FS.close(stream);
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }
    var doReadv = (stream, iov, iovcnt, offset) => {
      var ret = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = (growMemViews(), HEAPU32)[iov >> 2];
        var len = (growMemViews(), HEAPU32)[iov + 4 >> 2];
        iov += 8;
        var curr = FS.read(stream, (growMemViews(), HEAP8), ptr, len, offset);
        if (curr < 0) return -1;
        ret += curr;
        if (curr < len) break;
        if (typeof offset != "undefined") {
          offset += curr
        }
      }
      return ret
    };

    function xterm_pty_old_fd_read(fd, iov, iovcnt, pnum) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(28, 0, 1, fd, iov, iovcnt, pnum);
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        var num = doReadv(stream, iov, iovcnt);
        (growMemViews(), HEAPU32)[pnum >> 2] = num;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }
    var _fd_read = (fd, iov, iovcnt, pnum) => PTY_handleSleep(wakeUp => {
      let result = xterm_pty_old_fd_read(fd, iov, iovcnt, pnum);
      if (result === 1006) {
        PTY_waitForReadable(type => {
          switch (type) {
            case 0:
              wakeUp(xterm_pty_old_fd_read(fd, iov, iovcnt, pnum));
              break;
            case 1:
              wakeUp(27);
              break;
            case 2:
              wakeUp(0);
              break
          }
        })
      } else {
        wakeUp(result)
      }
    });

    function _fd_seek(fd, offset, whence, newOffset) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(29, 0, 1, fd, offset, whence, newOffset);
      offset = bigintToI53Checked(offset);
      try {
        if (isNaN(offset)) return 61;
        var stream = SYSCALLS.getStreamFromFD(fd);
        FS.llseek(stream, offset, whence);
        (growMemViews(), HEAP64)[newOffset >> 3] = BigInt(stream.position);
        if (stream.getdents && offset === 0 && whence === 0) stream.getdents = null;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _fd_sync(fd) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(30, 0, 1, fd);
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        if (stream.stream_ops?.fsync) {
          return stream.stream_ops.fsync(stream)
        }
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }
    var doWritev = (stream, iov, iovcnt, offset) => {
      var ret = 0;
      for (var i = 0; i < iovcnt; i++) {
        var ptr = (growMemViews(), HEAPU32)[iov >> 2];
        var len = (growMemViews(), HEAPU32)[iov + 4 >> 2];
        iov += 8;
        var curr = FS.write(stream, (growMemViews(), HEAP8), ptr, len, offset);
        if (curr < 0) return -1;
        ret += curr;
        if (curr < len) {
          break
        }
        if (typeof offset != "undefined") {
          offset += curr
        }
      }
      return ret
    };

    function _fd_write(fd, iov, iovcnt, pnum) {
      // if (ENVIRONMENT_IS_PTHREAD) return proxyToMainThread(31, 0, 1, fd, iov, iovcnt, pnum);
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        var num = doWritev(stream, iov, iovcnt);
        (growMemViews(), HEAPU32)[pnum >> 2] = num;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _random_get(buffer, size) {
      try {
        randomFill((growMemViews(), HEAPU8).subarray(buffer, buffer + size));
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }
    var stringToUTF8OnStack = str => {
      var size = lengthBytesUTF8(str) + 1;
      var ret = stackAlloc(size);
      stringToUTF8(str, ret, size);
      return ret
    };
    PThread.init();
    FS.createPreloadedFile = FS_createPreloadedFile;
    FS.staticInit();
    MEMFS.doesNotExistError = new FS.ErrnoError(44);
    MEMFS.doesNotExistError.stack = "<generic error, no stack>";
    {
      initMemory();
      if (Module["noExitRuntime"]) noExitRuntime = Module["noExitRuntime"];
      if (Module["preloadPlugins"]) preloadPlugins = Module["preloadPlugins"];
      if (Module["print"]) out = Module["print"];
      if (Module["printErr"]) err = Module["printErr"];
      if (Module["wasmBinary"]) wasmBinary = Module["wasmBinary"];
      if (Module["arguments"]) arguments_ = Module["arguments"];
      if (Module["thisProgram"]) thisProgram = Module["thisProgram"]
    }
    var proxiedFunctionTable = [_proc_exit, exitOnMainThread, pthreadCreateProxied, ___syscall_chdir, ___syscall_dup, ___syscall_dup3, ___syscall_faccessat, ___syscall_fcntl64, ___syscall_fstat64, ___syscall_ftruncate64, ___syscall_getcwd, ___syscall_getdents64, ___syscall_ioctl, ___syscall_lstat64, ___syscall_mkdirat, ___syscall_newfstatat, ___syscall_openat, xterm_pty_old_poll, PTY_waitForReadableWithAtomicImpl, ___syscall_readlinkat, ___syscall_stat64, ___syscall_statfs64, ___syscall_truncate64, ___syscall_unlinkat, ___syscall_utimensat, _environ_get, _environ_sizes_get, _fd_close, xterm_pty_old_fd_read, _fd_seek, _fd_sync, _fd_write];
    var wasmImports;

    function assignWasmImports() {
      wasmImports = {
        g: ___assert_fail,
        A: ___call_sighandler,
        k: ___cxa_throw,
        E: ___pthread_create_js,
        n: ___syscall_chdir,
        l: ___syscall_dup,
        Z: ___syscall_dup3,
        X: ___syscall_faccessat,
        c: ___syscall_fcntl64,
        V: ___syscall_fstat64,
        Q: ___syscall_ftruncate64,
        P: ___syscall_getcwd,
        O: ___syscall_getdents64,
        h: ___syscall_ioctl,
        S: ___syscall_lstat64,
        J: ___syscall_mkdirat,
        T: ___syscall_newfstatat,
        I: ___syscall_openat,
        H: ___syscall_poll,
        z: ___syscall_readlinkat,
        U: ___syscall_stat64,
        x: ___syscall_statfs64,
        v: ___syscall_truncate64,
        u: ___syscall_unlinkat,
        t: ___syscall_utimensat,
        p: __abort_js,
        M: __emscripten_init_main_thread_js,
        w: __emscripten_notify_mailbox_postmessage,
        G: __emscripten_receive_on_main_thread_js,
        C: __emscripten_runtime_keepalive_clear,
        D: __emscripten_thread_cleanup,
        L: __emscripten_thread_mailbox_await,
        j: __emscripten_thread_set_strongref,
        o: __tzset_js,
        m: _clock_time_get,
        F: _emscripten_check_blocking_allowed,
        Y: _emscripten_date_now,
        W: _emscripten_exit_with_live_runtime,
        b: _emscripten_get_now,
        s: _emscripten_resize_heap,
        y: _emscripten_runtime_keepalive_check,
        q: _environ_get,
        r: _environ_sizes_get,
        e: _exit,
        f: _fd_close,
        i: _fd_read,
        K: _fd_seek,
        R: _fd_sync,
        d: _fd_write,
        a: wasmMemory,
        B: _proc_exit,
        N: _random_get
      }
    }
    var wasmExports = await createWasm();
    var ___wasm_call_ctors = () => (___wasm_call_ctors = wasmExports["_"])();
    var ___remill_flag_computation_overflow = Module["___remill_flag_computation_overflow"] = (a0, a1) => (___remill_flag_computation_overflow = Module["___remill_flag_computation_overflow"] = wasmExports["$"])(a0, a1);
    var ___remill_barrier_store_store = Module["___remill_barrier_store_store"] = a0 => (___remill_barrier_store_store = Module["___remill_barrier_store_store"] = wasmExports["aa"])(a0);
    var ___remill_barrier_load_store = Module["___remill_barrier_load_store"] = a0 => (___remill_barrier_load_store = Module["___remill_barrier_load_store"] = wasmExports["ba"])(a0);
    var ___remill_syscall_tranpoline_call = Module["___remill_syscall_tranpoline_call"] = (a0, a1, a2) => (___remill_syscall_tranpoline_call = Module["___remill_syscall_tranpoline_call"] = wasmExports["ca"])(a0, a1, a2);
    var ___remill_read_memory_8 = Module["___remill_read_memory_8"] = (a0, a1) => (___remill_read_memory_8 = Module["___remill_read_memory_8"] = wasmExports["da"])(a0, a1);
    var ___remill_read_memory_16 = Module["___remill_read_memory_16"] = (a0, a1) => (___remill_read_memory_16 = Module["___remill_read_memory_16"] = wasmExports["ea"])(a0, a1);
    var ___remill_read_memory_32 = Module["___remill_read_memory_32"] = (a0, a1) => (___remill_read_memory_32 = Module["___remill_read_memory_32"] = wasmExports["fa"])(a0, a1);
    var ___remill_read_memory_64 = Module["___remill_read_memory_64"] = (a0, a1) => (___remill_read_memory_64 = Module["___remill_read_memory_64"] = wasmExports["ga"])(a0, a1);
    var ___remill_read_memory_128 = Module["___remill_read_memory_128"] = (a0, a1, a2) => (___remill_read_memory_128 = Module["___remill_read_memory_128"] = wasmExports["ha"])(a0, a1, a2);
    var ___remill_write_memory_8 = Module["___remill_write_memory_8"] = (a0, a1, a2) => (___remill_write_memory_8 = Module["___remill_write_memory_8"] = wasmExports["ia"])(a0, a1, a2);
    var ___remill_write_memory_16 = Module["___remill_write_memory_16"] = (a0, a1, a2) => (___remill_write_memory_16 = Module["___remill_write_memory_16"] = wasmExports["ja"])(a0, a1, a2);
    var ___remill_write_memory_32 = Module["___remill_write_memory_32"] = (a0, a1, a2) => (___remill_write_memory_32 = Module["___remill_write_memory_32"] = wasmExports["ka"])(a0, a1, a2);
    var ___remill_write_memory_64 = Module["___remill_write_memory_64"] = (a0, a1, a2) => (___remill_write_memory_64 = Module["___remill_write_memory_64"] = wasmExports["la"])(a0, a1, a2);
    var ___remill_write_memory_128 = Module["___remill_write_memory_128"] = (a0, a1, a2, a3) => (___remill_write_memory_128 = Module["___remill_write_memory_128"] = wasmExports["ma"])(a0, a1, a2, a3);
    var ___remill_read_memory_f32 = Module["___remill_read_memory_f32"] = (a0, a1) => (___remill_read_memory_f32 = Module["___remill_read_memory_f32"] = wasmExports["na"])(a0, a1);
    var ___remill_read_memory_f64 = Module["___remill_read_memory_f64"] = (a0, a1) => (___remill_read_memory_f64 = Module["___remill_read_memory_f64"] = wasmExports["oa"])(a0, a1);
    var ___remill_read_memory_f128 = Module["___remill_read_memory_f128"] = (a0, a1) => (___remill_read_memory_f128 = Module["___remill_read_memory_f128"] = wasmExports["pa"])(a0, a1);
    var ___remill_write_memory_f32 = Module["___remill_write_memory_f32"] = (a0, a1, a2) => (___remill_write_memory_f32 = Module["___remill_write_memory_f32"] = wasmExports["qa"])(a0, a1, a2);
    var ___remill_write_memory_f64 = Module["___remill_write_memory_f64"] = (a0, a1, a2) => (___remill_write_memory_f64 = Module["___remill_write_memory_f64"] = wasmExports["ra"])(a0, a1, a2);
    var ___remill_write_memory_f128 = Module["___remill_write_memory_f128"] = (a0, a1, a2) => (___remill_write_memory_f128 = Module["___remill_write_memory_f128"] = wasmExports["sa"])(a0, a1, a2);
    var ___remill_barrier_load_load = Module["___remill_barrier_load_load"] = a0 => (___remill_barrier_load_load = Module["___remill_barrier_load_load"] = wasmExports["ta"])(a0);
    var ___remill_barrier_store_load = Module["___remill_barrier_store_load"] = a0 => (___remill_barrier_store_load = Module["___remill_barrier_store_load"] = wasmExports["ua"])(a0);
    var ___remill_atomic_begin = Module["___remill_atomic_begin"] = a0 => (___remill_atomic_begin = Module["___remill_atomic_begin"] = wasmExports["va"])(a0);
    var ___remill_atomic_end = Module["___remill_atomic_end"] = a0 => (___remill_atomic_end = Module["___remill_atomic_end"] = wasmExports["wa"])(a0);
    var ___remill_delay_slot_begin = Module["___remill_delay_slot_begin"] = a0 => (___remill_delay_slot_begin = Module["___remill_delay_slot_begin"] = wasmExports["xa"])(a0);
    var ___remill_delay_slot_end = Module["___remill_delay_slot_end"] = a0 => (___remill_delay_slot_end = Module["___remill_delay_slot_end"] = wasmExports["ya"])(a0);
    var ___remill_compare_exchange_memory_8 = Module["___remill_compare_exchange_memory_8"] = (a0, a1, a2, a3) => (___remill_compare_exchange_memory_8 = Module["___remill_compare_exchange_memory_8"] = wasmExports["za"])(a0, a1, a2, a3);
    var ___remill_compare_exchange_memory_16 = Module["___remill_compare_exchange_memory_16"] = (a0, a1, a2, a3) => (___remill_compare_exchange_memory_16 = Module["___remill_compare_exchange_memory_16"] = wasmExports["Aa"])(a0, a1, a2, a3);
    var ___remill_compare_exchange_memory_32 = Module["___remill_compare_exchange_memory_32"] = (a0, a1, a2, a3) => (___remill_compare_exchange_memory_32 = Module["___remill_compare_exchange_memory_32"] = wasmExports["Ba"])(a0, a1, a2, a3);
    var ___remill_compare_exchange_memory_64 = Module["___remill_compare_exchange_memory_64"] = (a0, a1, a2, a3) => (___remill_compare_exchange_memory_64 = Module["___remill_compare_exchange_memory_64"] = wasmExports["Ca"])(a0, a1, a2, a3);
    var ___remill_fetch_and_add_8 = Module["___remill_fetch_and_add_8"] = (a0, a1, a2) => (___remill_fetch_and_add_8 = Module["___remill_fetch_and_add_8"] = wasmExports["Da"])(a0, a1, a2);
    var ___remill_fetch_and_add_16 = Module["___remill_fetch_and_add_16"] = (a0, a1, a2) => (___remill_fetch_and_add_16 = Module["___remill_fetch_and_add_16"] = wasmExports["Ea"])(a0, a1, a2);
    var ___remill_fetch_and_add_32 = Module["___remill_fetch_and_add_32"] = (a0, a1, a2) => (___remill_fetch_and_add_32 = Module["___remill_fetch_and_add_32"] = wasmExports["Fa"])(a0, a1, a2);
    var ___remill_fetch_and_add_64 = Module["___remill_fetch_and_add_64"] = (a0, a1, a2) => (___remill_fetch_and_add_64 = Module["___remill_fetch_and_add_64"] = wasmExports["Ga"])(a0, a1, a2);
    var ___remill_fetch_and_sub_8 = Module["___remill_fetch_and_sub_8"] = (a0, a1, a2) => (___remill_fetch_and_sub_8 = Module["___remill_fetch_and_sub_8"] = wasmExports["Ha"])(a0, a1, a2);
    var ___remill_fetch_and_sub_16 = Module["___remill_fetch_and_sub_16"] = (a0, a1, a2) => (___remill_fetch_and_sub_16 = Module["___remill_fetch_and_sub_16"] = wasmExports["Ia"])(a0, a1, a2);
    var ___remill_fetch_and_sub_32 = Module["___remill_fetch_and_sub_32"] = (a0, a1, a2) => (___remill_fetch_and_sub_32 = Module["___remill_fetch_and_sub_32"] = wasmExports["Ja"])(a0, a1, a2);
    var ___remill_fetch_and_sub_64 = Module["___remill_fetch_and_sub_64"] = (a0, a1, a2) => (___remill_fetch_and_sub_64 = Module["___remill_fetch_and_sub_64"] = wasmExports["Ka"])(a0, a1, a2);
    var ___remill_fetch_and_or_8 = Module["___remill_fetch_and_or_8"] = (a0, a1, a2) => (___remill_fetch_and_or_8 = Module["___remill_fetch_and_or_8"] = wasmExports["La"])(a0, a1, a2);
    var ___remill_fetch_and_or_16 = Module["___remill_fetch_and_or_16"] = (a0, a1, a2) => (___remill_fetch_and_or_16 = Module["___remill_fetch_and_or_16"] = wasmExports["Ma"])(a0, a1, a2);
    var ___remill_fetch_and_or_32 = Module["___remill_fetch_and_or_32"] = (a0, a1, a2) => (___remill_fetch_and_or_32 = Module["___remill_fetch_and_or_32"] = wasmExports["Na"])(a0, a1, a2);
    var ___remill_fetch_and_or_64 = Module["___remill_fetch_and_or_64"] = (a0, a1, a2) => (___remill_fetch_and_or_64 = Module["___remill_fetch_and_or_64"] = wasmExports["Oa"])(a0, a1, a2);
    var ___remill_fetch_and_and_8 = Module["___remill_fetch_and_and_8"] = (a0, a1, a2) => (___remill_fetch_and_and_8 = Module["___remill_fetch_and_and_8"] = wasmExports["Pa"])(a0, a1, a2);
    var ___remill_fetch_and_and_16 = Module["___remill_fetch_and_and_16"] = (a0, a1, a2) => (___remill_fetch_and_and_16 = Module["___remill_fetch_and_and_16"] = wasmExports["Qa"])(a0, a1, a2);
    var ___remill_fetch_and_and_32 = Module["___remill_fetch_and_and_32"] = (a0, a1, a2) => (___remill_fetch_and_and_32 = Module["___remill_fetch_and_and_32"] = wasmExports["Ra"])(a0, a1, a2);
    var ___remill_fetch_and_and_64 = Module["___remill_fetch_and_and_64"] = (a0, a1, a2) => (___remill_fetch_and_and_64 = Module["___remill_fetch_and_and_64"] = wasmExports["Sa"])(a0, a1, a2);
    var ___remill_fetch_and_xor_8 = Module["___remill_fetch_and_xor_8"] = (a0, a1, a2) => (___remill_fetch_and_xor_8 = Module["___remill_fetch_and_xor_8"] = wasmExports["Ta"])(a0, a1, a2);
    var ___remill_fetch_and_xor_16 = Module["___remill_fetch_and_xor_16"] = (a0, a1, a2) => (___remill_fetch_and_xor_16 = Module["___remill_fetch_and_xor_16"] = wasmExports["Ua"])(a0, a1, a2);
    var ___remill_fetch_and_xor_32 = Module["___remill_fetch_and_xor_32"] = (a0, a1, a2) => (___remill_fetch_and_xor_32 = Module["___remill_fetch_and_xor_32"] = wasmExports["Va"])(a0, a1, a2);
    var ___remill_fetch_and_xor_64 = Module["___remill_fetch_and_xor_64"] = (a0, a1, a2) => (___remill_fetch_and_xor_64 = Module["___remill_fetch_and_xor_64"] = wasmExports["Wa"])(a0, a1, a2);
    var ___remill_fpu_exception_test_and_clear = Module["___remill_fpu_exception_test_and_clear"] = (a0, a1) => (___remill_fpu_exception_test_and_clear = Module["___remill_fpu_exception_test_and_clear"] = wasmExports["Xa"])(a0, a1);
    var ___remill_error = Module["___remill_error"] = (a0, a1, a2, a3) => (___remill_error = Module["___remill_error"] = wasmExports["Ya"])(a0, a1, a2, a3);
    var ___remill_function_call = Module["___remill_function_call"] = (a0, a1, a2, a3) => (___remill_function_call = Module["___remill_function_call"] = wasmExports["Za"])(a0, a1, a2, a3);
    var ___remill_function_return = Module["___remill_function_return"] = (a0, a1, a2, a3) => (___remill_function_return = Module["___remill_function_return"] = wasmExports["_a"])(a0, a1, a2, a3);
    var ___remill_jump = Module["___remill_jump"] = (a0, a1, a2, a3) => (___remill_jump = Module["___remill_jump"] = wasmExports["$a"])(a0, a1, a2, a3);
    var ___remill_missing_block = Module["___remill_missing_block"] = (a0, a1, a2, a3) => (___remill_missing_block = Module["___remill_missing_block"] = wasmExports["ab"])(a0, a1, a2, a3);
    var __ecv_func_epilogue = Module["__ecv_func_epilogue"] = (a0, a1, a2, a3) => (__ecv_func_epilogue = Module["__ecv_func_epilogue"] = wasmExports["bb"])(a0, a1, a2, a3);
    var ___remill_async_hyper_call = Module["___remill_async_hyper_call"] = (a0, a1, a2, a3) => (___remill_async_hyper_call = Module["___remill_async_hyper_call"] = wasmExports["cb"])(a0, a1, a2, a3);
    var ___remill_undefined_8 = Module["___remill_undefined_8"] = () => (___remill_undefined_8 = Module["___remill_undefined_8"] = wasmExports["db"])();
    var ___remill_undefined_16 = Module["___remill_undefined_16"] = () => (___remill_undefined_16 = Module["___remill_undefined_16"] = wasmExports["eb"])();
    var ___remill_undefined_32 = Module["___remill_undefined_32"] = () => (___remill_undefined_32 = Module["___remill_undefined_32"] = wasmExports["fb"])();
    var ___remill_undefined_64 = Module["___remill_undefined_64"] = () => (___remill_undefined_64 = Module["___remill_undefined_64"] = wasmExports["gb"])();
    var ___remill_undefined_f32 = Module["___remill_undefined_f32"] = () => (___remill_undefined_f32 = Module["___remill_undefined_f32"] = wasmExports["hb"])();
    var ___remill_undefined_f64 = Module["___remill_undefined_f64"] = () => (___remill_undefined_f64 = Module["___remill_undefined_f64"] = wasmExports["ib"])();
    var ___remill_flag_computation_zero = Module["___remill_flag_computation_zero"] = (a0, a1) => (___remill_flag_computation_zero = Module["___remill_flag_computation_zero"] = wasmExports["jb"])(a0, a1);
    var ___remill_flag_computation_sign = Module["___remill_flag_computation_sign"] = (a0, a1) => (___remill_flag_computation_sign = Module["___remill_flag_computation_sign"] = wasmExports["kb"])(a0, a1);
    var ___remill_flag_computation_carry = Module["___remill_flag_computation_carry"] = (a0, a1) => (___remill_flag_computation_carry = Module["___remill_flag_computation_carry"] = wasmExports["lb"])(a0, a1);
    var ___remill_compare_sle = Module["___remill_compare_sle"] = a0 => (___remill_compare_sle = Module["___remill_compare_sle"] = wasmExports["mb"])(a0);
    var ___remill_compare_slt = Module["___remill_compare_slt"] = a0 => (___remill_compare_slt = Module["___remill_compare_slt"] = wasmExports["nb"])(a0);
    var ___remill_compare_sgt = Module["___remill_compare_sgt"] = a0 => (___remill_compare_sgt = Module["___remill_compare_sgt"] = wasmExports["ob"])(a0);
    var ___remill_compare_sge = Module["___remill_compare_sge"] = a0 => (___remill_compare_sge = Module["___remill_compare_sge"] = wasmExports["pb"])(a0);
    var ___remill_compare_eq = Module["___remill_compare_eq"] = a0 => (___remill_compare_eq = Module["___remill_compare_eq"] = wasmExports["qb"])(a0);
    var ___remill_compare_neq = Module["___remill_compare_neq"] = a0 => (___remill_compare_neq = Module["___remill_compare_neq"] = wasmExports["rb"])(a0);
    var ___remill_compare_ugt = Module["___remill_compare_ugt"] = a0 => (___remill_compare_ugt = Module["___remill_compare_ugt"] = wasmExports["sb"])(a0);
    var ___remill_compare_uge = Module["___remill_compare_uge"] = a0 => (___remill_compare_uge = Module["___remill_compare_uge"] = wasmExports["tb"])(a0);
    var ___remill_compare_ult = Module["___remill_compare_ult"] = a0 => (___remill_compare_ult = Module["___remill_compare_ult"] = wasmExports["ub"])(a0);
    var ___remill_compare_ule = Module["___remill_compare_ule"] = a0 => (___remill_compare_ule = Module["___remill_compare_ule"] = wasmExports["vb"])(a0);
    var ___remill_x86_set_segment_es = Module["___remill_x86_set_segment_es"] = a0 => (___remill_x86_set_segment_es = Module["___remill_x86_set_segment_es"] = wasmExports["wb"])(a0);
    var ___remill_x86_set_segment_ss = Module["___remill_x86_set_segment_ss"] = a0 => (___remill_x86_set_segment_ss = Module["___remill_x86_set_segment_ss"] = wasmExports["xb"])(a0);
    var ___remill_x86_set_segment_ds = Module["___remill_x86_set_segment_ds"] = a0 => (___remill_x86_set_segment_ds = Module["___remill_x86_set_segment_ds"] = wasmExports["yb"])(a0);
    var ___remill_x86_set_segment_fs = Module["___remill_x86_set_segment_fs"] = a0 => (___remill_x86_set_segment_fs = Module["___remill_x86_set_segment_fs"] = wasmExports["zb"])(a0);
    var ___remill_x86_set_segment_gs = Module["___remill_x86_set_segment_gs"] = a0 => (___remill_x86_set_segment_gs = Module["___remill_x86_set_segment_gs"] = wasmExports["Ab"])(a0);
    var ___remill_x86_set_debug_reg = Module["___remill_x86_set_debug_reg"] = a0 => (___remill_x86_set_debug_reg = Module["___remill_x86_set_debug_reg"] = wasmExports["Bb"])(a0);
    var ___remill_x86_set_control_reg_0 = Module["___remill_x86_set_control_reg_0"] = a0 => (___remill_x86_set_control_reg_0 = Module["___remill_x86_set_control_reg_0"] = wasmExports["Cb"])(a0);
    var ___remill_x86_set_control_reg_1 = Module["___remill_x86_set_control_reg_1"] = a0 => (___remill_x86_set_control_reg_1 = Module["___remill_x86_set_control_reg_1"] = wasmExports["Db"])(a0);
    var ___remill_x86_set_control_reg_2 = Module["___remill_x86_set_control_reg_2"] = a0 => (___remill_x86_set_control_reg_2 = Module["___remill_x86_set_control_reg_2"] = wasmExports["Eb"])(a0);
    var ___remill_x86_set_control_reg_3 = Module["___remill_x86_set_control_reg_3"] = a0 => (___remill_x86_set_control_reg_3 = Module["___remill_x86_set_control_reg_3"] = wasmExports["Fb"])(a0);
    var ___remill_x86_set_control_reg_4 = Module["___remill_x86_set_control_reg_4"] = a0 => (___remill_x86_set_control_reg_4 = Module["___remill_x86_set_control_reg_4"] = wasmExports["Gb"])(a0);
    var ___remill_amd64_set_debug_reg = Module["___remill_amd64_set_debug_reg"] = a0 => (___remill_amd64_set_debug_reg = Module["___remill_amd64_set_debug_reg"] = wasmExports["Hb"])(a0);
    var ___remill_amd64_set_control_reg_0 = Module["___remill_amd64_set_control_reg_0"] = a0 => (___remill_amd64_set_control_reg_0 = Module["___remill_amd64_set_control_reg_0"] = wasmExports["Ib"])(a0);
    var ___remill_amd64_set_control_reg_1 = Module["___remill_amd64_set_control_reg_1"] = a0 => (___remill_amd64_set_control_reg_1 = Module["___remill_amd64_set_control_reg_1"] = wasmExports["Jb"])(a0);
    var ___remill_amd64_set_control_reg_2 = Module["___remill_amd64_set_control_reg_2"] = a0 => (___remill_amd64_set_control_reg_2 = Module["___remill_amd64_set_control_reg_2"] = wasmExports["Kb"])(a0);
    var ___remill_amd64_set_control_reg_3 = Module["___remill_amd64_set_control_reg_3"] = a0 => (___remill_amd64_set_control_reg_3 = Module["___remill_amd64_set_control_reg_3"] = wasmExports["Lb"])(a0);
    var ___remill_amd64_set_control_reg_4 = Module["___remill_amd64_set_control_reg_4"] = a0 => (___remill_amd64_set_control_reg_4 = Module["___remill_amd64_set_control_reg_4"] = wasmExports["Mb"])(a0);
    var ___remill_amd64_set_control_reg_8 = Module["___remill_amd64_set_control_reg_8"] = a0 => (___remill_amd64_set_control_reg_8 = Module["___remill_amd64_set_control_reg_8"] = wasmExports["Nb"])(a0);
    var ___remill_aarch64_emulate_instruction = Module["___remill_aarch64_emulate_instruction"] = a0 => (___remill_aarch64_emulate_instruction = Module["___remill_aarch64_emulate_instruction"] = wasmExports["Ob"])(a0);
    var ___remill_aarch32_emulate_instruction = Module["___remill_aarch32_emulate_instruction"] = a0 => (___remill_aarch32_emulate_instruction = Module["___remill_aarch32_emulate_instruction"] = wasmExports["Pb"])(a0);
    var ___remill_aarch32_check_not_el2 = Module["___remill_aarch32_check_not_el2"] = a0 => (___remill_aarch32_check_not_el2 = Module["___remill_aarch32_check_not_el2"] = wasmExports["Qb"])(a0);
    var ___remill_sparc_set_asi_register = Module["___remill_sparc_set_asi_register"] = a0 => (___remill_sparc_set_asi_register = Module["___remill_sparc_set_asi_register"] = wasmExports["Rb"])(a0);
    var ___remill_sparc_unimplemented_instruction = Module["___remill_sparc_unimplemented_instruction"] = a0 => (___remill_sparc_unimplemented_instruction = Module["___remill_sparc_unimplemented_instruction"] = wasmExports["Sb"])(a0);
    var ___remill_sparc_unhandled_dcti = Module["___remill_sparc_unhandled_dcti"] = a0 => (___remill_sparc_unhandled_dcti = Module["___remill_sparc_unhandled_dcti"] = wasmExports["Tb"])(a0);
    var ___remill_sparc_window_underflow = Module["___remill_sparc_window_underflow"] = a0 => (___remill_sparc_window_underflow = Module["___remill_sparc_window_underflow"] = wasmExports["Ub"])(a0);
    var ___remill_sparc_trap_cond_a = Module["___remill_sparc_trap_cond_a"] = a0 => (___remill_sparc_trap_cond_a = Module["___remill_sparc_trap_cond_a"] = wasmExports["Vb"])(a0);
    var ___remill_sparc_trap_cond_n = Module["___remill_sparc_trap_cond_n"] = a0 => (___remill_sparc_trap_cond_n = Module["___remill_sparc_trap_cond_n"] = wasmExports["Wb"])(a0);
    var ___remill_sparc_trap_cond_ne = Module["___remill_sparc_trap_cond_ne"] = a0 => (___remill_sparc_trap_cond_ne = Module["___remill_sparc_trap_cond_ne"] = wasmExports["Xb"])(a0);
    var ___remill_sparc_trap_cond_e = Module["___remill_sparc_trap_cond_e"] = a0 => (___remill_sparc_trap_cond_e = Module["___remill_sparc_trap_cond_e"] = wasmExports["Yb"])(a0);
    var ___remill_sparc_trap_cond_g = Module["___remill_sparc_trap_cond_g"] = a0 => (___remill_sparc_trap_cond_g = Module["___remill_sparc_trap_cond_g"] = wasmExports["Zb"])(a0);
    var ___remill_sparc_trap_cond_le = Module["___remill_sparc_trap_cond_le"] = a0 => (___remill_sparc_trap_cond_le = Module["___remill_sparc_trap_cond_le"] = wasmExports["_b"])(a0);
    var ___remill_sparc_trap_cond_ge = Module["___remill_sparc_trap_cond_ge"] = a0 => (___remill_sparc_trap_cond_ge = Module["___remill_sparc_trap_cond_ge"] = wasmExports["$b"])(a0);
    var ___remill_sparc_trap_cond_l = Module["___remill_sparc_trap_cond_l"] = a0 => (___remill_sparc_trap_cond_l = Module["___remill_sparc_trap_cond_l"] = wasmExports["ac"])(a0);
    var ___remill_sparc_trap_cond_gu = Module["___remill_sparc_trap_cond_gu"] = a0 => (___remill_sparc_trap_cond_gu = Module["___remill_sparc_trap_cond_gu"] = wasmExports["bc"])(a0);
    var ___remill_sparc_trap_cond_leu = Module["___remill_sparc_trap_cond_leu"] = a0 => (___remill_sparc_trap_cond_leu = Module["___remill_sparc_trap_cond_leu"] = wasmExports["cc"])(a0);
    var ___remill_sparc_trap_cond_cc = Module["___remill_sparc_trap_cond_cc"] = a0 => (___remill_sparc_trap_cond_cc = Module["___remill_sparc_trap_cond_cc"] = wasmExports["dc"])(a0);
    var ___remill_sparc_trap_cond_cs = Module["___remill_sparc_trap_cond_cs"] = a0 => (___remill_sparc_trap_cond_cs = Module["___remill_sparc_trap_cond_cs"] = wasmExports["ec"])(a0);
    var ___remill_sparc_trap_cond_pos = Module["___remill_sparc_trap_cond_pos"] = a0 => (___remill_sparc_trap_cond_pos = Module["___remill_sparc_trap_cond_pos"] = wasmExports["fc"])(a0);
    var ___remill_sparc_trap_cond_neg = Module["___remill_sparc_trap_cond_neg"] = a0 => (___remill_sparc_trap_cond_neg = Module["___remill_sparc_trap_cond_neg"] = wasmExports["gc"])(a0);
    var ___remill_sparc_trap_cond_vc = Module["___remill_sparc_trap_cond_vc"] = a0 => (___remill_sparc_trap_cond_vc = Module["___remill_sparc_trap_cond_vc"] = wasmExports["hc"])(a0);
    var ___remill_sparc_trap_cond_vs = Module["___remill_sparc_trap_cond_vs"] = a0 => (___remill_sparc_trap_cond_vs = Module["___remill_sparc_trap_cond_vs"] = wasmExports["ic"])(a0);
    var ___remill_sparc32_emulate_instruction = Module["___remill_sparc32_emulate_instruction"] = a0 => (___remill_sparc32_emulate_instruction = Module["___remill_sparc32_emulate_instruction"] = wasmExports["jc"])(a0);
    var ___remill_sparc64_emulate_instruction = Module["___remill_sparc64_emulate_instruction"] = a0 => (___remill_sparc64_emulate_instruction = Module["___remill_sparc64_emulate_instruction"] = wasmExports["kc"])(a0);
    var _main = Module["_main"] = (a0, a1) => (_main = Module["_main"] = wasmExports["mc"])(a0, a1);
    var _malloc = a0 => (_malloc = wasmExports["nc"])(a0);
    var ___remill_undefined_f128 = Module["___remill_undefined_f128"] = () => (___remill_undefined_f128 = Module["___remill_undefined_f128"] = wasmExports["oc"])();
    var ___remill_compare_exchange_memory_128 = Module["___remill_compare_exchange_memory_128"] = (a0, a1, a2, a3) => (___remill_compare_exchange_memory_128 = Module["___remill_compare_exchange_memory_128"] = wasmExports["pc"])(a0, a1, a2, a3);
    var ___remill_fetch_and_nand_8 = Module["___remill_fetch_and_nand_8"] = (a0, a1, a2) => (___remill_fetch_and_nand_8 = Module["___remill_fetch_and_nand_8"] = wasmExports["qc"])(a0, a1, a2);
    var ___remill_fetch_and_nand_16 = Module["___remill_fetch_and_nand_16"] = (a0, a1, a2) => (___remill_fetch_and_nand_16 = Module["___remill_fetch_and_nand_16"] = wasmExports["rc"])(a0, a1, a2);
    var ___remill_fetch_and_nand_32 = Module["___remill_fetch_and_nand_32"] = (a0, a1, a2) => (___remill_fetch_and_nand_32 = Module["___remill_fetch_and_nand_32"] = wasmExports["sc"])(a0, a1, a2);
    var ___remill_fetch_and_nand_64 = Module["___remill_fetch_and_nand_64"] = (a0, a1, a2) => (___remill_fetch_and_nand_64 = Module["___remill_fetch_and_nand_64"] = wasmExports["tc"])(a0, a1, a2);
    var ___remill_read_io_port_8 = Module["___remill_read_io_port_8"] = (a0, a1) => (___remill_read_io_port_8 = Module["___remill_read_io_port_8"] = wasmExports["uc"])(a0, a1);
    var ___remill_read_io_port_16 = Module["___remill_read_io_port_16"] = (a0, a1) => (___remill_read_io_port_16 = Module["___remill_read_io_port_16"] = wasmExports["vc"])(a0, a1);
    var ___remill_read_io_port_32 = Module["___remill_read_io_port_32"] = (a0, a1) => (___remill_read_io_port_32 = Module["___remill_read_io_port_32"] = wasmExports["wc"])(a0, a1);
    var ___remill_write_io_port_8 = Module["___remill_write_io_port_8"] = (a0, a1, a2) => (___remill_write_io_port_8 = Module["___remill_write_io_port_8"] = wasmExports["xc"])(a0, a1, a2);
    var ___remill_write_io_port_16 = Module["___remill_write_io_port_16"] = (a0, a1, a2) => (___remill_write_io_port_16 = Module["___remill_write_io_port_16"] = wasmExports["yc"])(a0, a1, a2);
    var ___remill_write_io_port_32 = Module["___remill_write_io_port_32"] = (a0, a1, a2) => (___remill_write_io_port_32 = Module["___remill_write_io_port_32"] = wasmExports["zc"])(a0, a1, a2);
    var ___remill_ppc_emulate_instruction = Module["___remill_ppc_emulate_instruction"] = a0 => (___remill_ppc_emulate_instruction = Module["___remill_ppc_emulate_instruction"] = wasmExports["Ac"])(a0);
    var ___remill_ppc_syscall = Module["___remill_ppc_syscall"] = a0 => (___remill_ppc_syscall = Module["___remill_ppc_syscall"] = wasmExports["Bc"])(a0);
    var __emscripten_tls_init = () => (__emscripten_tls_init = wasmExports["Cc"])();
    var _pthread_self = () => (_pthread_self = wasmExports["Dc"])();
    var __emscripten_proxy_main = Module["__emscripten_proxy_main"] = (a0, a1) => (__emscripten_proxy_main = Module["__emscripten_proxy_main"] = wasmExports["Ec"])(a0, a1);
    var __emscripten_thread_init = (a0, a1, a2, a3, a4, a5) => (__emscripten_thread_init = wasmExports["Fc"])(a0, a1, a2, a3, a4, a5);
    var __emscripten_thread_crashed = () => (__emscripten_thread_crashed = wasmExports["Gc"])();
    var _raise = a0 => (_raise = wasmExports["Hc"])(a0);
    var __emscripten_run_on_main_thread_js = (a0, a1, a2, a3, a4) => (__emscripten_run_on_main_thread_js = wasmExports["Ic"])(a0, a1, a2, a3, a4);
    var __emscripten_thread_free_data = a0 => (__emscripten_thread_free_data = wasmExports["Jc"])(a0);
    var __emscripten_thread_exit = a0 => (__emscripten_thread_exit = wasmExports["Kc"])(a0);
    var __emscripten_check_mailbox = () => (__emscripten_check_mailbox = wasmExports["Lc"])();
    var _emscripten_stack_set_limits = (a0, a1) => (_emscripten_stack_set_limits = wasmExports["Mc"])(a0, a1);
    var __emscripten_stack_restore = a0 => (__emscripten_stack_restore = wasmExports["Nc"])(a0);
    var __emscripten_stack_alloc = a0 => (__emscripten_stack_alloc = wasmExports["Oc"])(a0);
    var _emscripten_stack_get_current = () => (_emscripten_stack_get_current = wasmExports["Pc"])();

    function callMain(args = []) {
      var entryFunction = __emscripten_proxy_main;
      runtimeKeepalivePush();
      args.unshift(thisProgram);
      var argc = args.length;
      var argv = stackAlloc((argc + 1) * 4);
      var argv_ptr = argv;
      args.forEach(arg => {
        (growMemViews(), HEAPU32)[argv_ptr >> 2] = stringToUTF8OnStack(arg);
        argv_ptr += 4
      });
      (growMemViews(), HEAPU32)[argv_ptr >> 2] = 0;
      try {
        var ret = entryFunction(argc, argv);
        exitJS(ret, true);
        return ret
      } catch (e) {
        return handleException(e)
      }
    }

    function run(args = arguments_) {
      if (runDependencies > 0) {
        dependenciesFulfilled = run;
        return
      }
      // if (ENVIRONMENT_IS_PTHREAD) {
      //   readyPromiseResolve(Module);
      //   initRuntime();
      //   return
      // }
      preRun();
      if (runDependencies > 0) {
        dependenciesFulfilled = run;
        return
      }

      function doRun() {
        Module["calledRun"] = true;
        if (ABORT) return;
        initRuntime();
        preMain();
        readyPromiseResolve(Module);
        Module["onRuntimeInitialized"]?.();
        var noInitialRun = Module["noInitialRun"] || false;
        if (!noInitialRun) callMain(args);
        postRun()
      }
      if (Module["setStatus"]) {
        Module["setStatus"]("Running...");
        setTimeout(() => {
          setTimeout(() => Module["setStatus"](""), 1);
          doRun()
        }, 1)
      } else {
        doRun()
      }
    }

    function preInit() {
      if (Module["preInit"]) {
        if (typeof Module["preInit"] == "function") Module["preInit"] = [Module["preInit"]];
        while (Module["preInit"].length > 0) {
          Module["preInit"].shift()()
        }
      }
    }
    preInit();
    run();
    console.log("self: ");
    console.log(self.constructor.name);
    moduleRtn = readyPromise;
    return moduleRtn;
  });
})();
export default Module;
var isPthread = globalThis.self?.name?.startsWith('em-pthread');
// When running as a pthread, construct a new instance on startup
isPthread && Module();