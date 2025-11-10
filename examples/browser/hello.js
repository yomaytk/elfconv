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
    var arguments_ = [];
    var thisProgram = "./hello.wasm";
    var quit_ = (status, toThrow) => {
      throw toThrow
    };
    var _scriptName = import.meta.url;
    var scriptDirectory = "";

    var wasmBinary;

    /// syscall-proxy.js 
    var GlobalSharedBuffer = undefined;
    var wasmMemory = undefined;
    var gMemoryBufView;
    var pMemory32View;

    // register the process of postMessage from js-kernel-proxy.
    self.onmessage = e => {
      let d = e["data"];
      if (d.cmd === "initMemory") {
        GlobalSharedBuffer = d.gMemoryBuf;
        wasmMemory = d.pWasmMemory;
        gMemoryBufView = new Int32Array(GlobalSharedBuffer);
        pMemory32View = new Int32Array(wasmMemory.buffer);
        assignWasmImports();
      } else if (d.cmd === "startWorker") {
        startWorker();
      }
    }

    function ecvProxySyscallJs(sysNum, ...callArgs) {

      // get shared array buffer for notification.
      // i32 [0]: head pointer to the necessary data on the shared memory
      // content of head pointer: [sysNum (8byte); argsNum (8byte); args (8 * sysNum byte); sysRval (8byte)]
      // i32 [1]: notification space. 0: js-kernel is waiting 1: js-kernel is waking up
      // i32 [2]: exec-side wait space

      console.log(`ecvProxySyscallJs start [sysNum: ${sysNum}] (hello.js).`);

      if (!GlobalSharedBuffer || !wasmMemory) {
        throw "Wasm memory have not been initialized yet.";
      }

      let sp = stackSave();
      let newAllocSz = 4 + 4 + callArgs.length * 4 + 4;
      let headPtr = stackAlloc(newAllocSz);
      let headPtr32 = headPtr >> 2;

      pMemory32View[headPtr32] = sysNum;

      let argsNum = 0;

      for (let i = 0; i < callArgs.length; i++) {
        // TODO update memory to the target exec worker.
        pMemory32View[headPtr32 + 2 + i] = callArgs[i];
        argsNum += 1;
      }

      pMemory32View[headPtr32 + 1] = argsNum;

      // save head pointer on the ExecMemory
      Atomics.store(gMemoryBufView, 0, headPtr32);
      // init exec-side wait space
      Atomics.store(gMemoryBufView, 2, 0);

      var jsKernelStatus = Atomics.load(gMemoryBufView, 1);
      if (jsKernelStatus != 0) {
        throw "js kernel has already waked up";
      }

      // notify (to js-kernel-proxy)
      Atomics.store(gMemoryBufView, 1, 1);
      Atomics.notify(gMemoryBufView, 1, 1);
      console.log("notify to js-kernel-proxy (hello.js).");

      // waiting for syscall finishing (of js-kernel-proxy).
      Atomics.wait(gMemoryBufView, 2, 0);

      // wake up (from js-kernel-proxy).
      let notifyVal = Atomics.load(gMemoryBufView, 2);
      if (notifyVal != 1) {
        throw `nofityVal (${notifyVal}) at ecvProxySyscallJs(sysNum, ...callArgs) is strange.`;
      }

      var sysRval = pMemory32View[headPtr32 + 2 + argsNum];
      console.log(`sysRval: ${sysRval}`);

      stackRestore(sp);
      return sysRval;
    }

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
    // var out = console.log.bind(console);
    var err = console.error.bind(console);
    var ABORT = false;
    var EXITSTATUS;
    var HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAP64, HEAPU64, HEAPF64;

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
      // runtimeInitialized = true;
      wasmExports["X"]();
    }

    function preMain() { }

    function postRun() {
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
        return locateFile("hello.wasm")
      }
      return new URL("hello.wasm", import.meta.url).href
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
        updateMemoryViews();
        wasmTable = wasmExports["ac"];
        removeRunDependency("wasm-instantiate");
        return wasmExports
      }
      addRunDependency("wasm-instantiate");

      function receiveInstantiationResult(result) {
        return receiveInstance(result["instance"])
      }
      var info = getWasmImports();
      if (Module["instantiateWasm"]) {
        return new Promise((resolve, reject) => {
          Module["instantiateWasm"](info, (mod, inst) => {
            resolve(receiveInstance(mod, inst))
          })
        })
      }
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
    var callRuntimeCallbacks = callbacks => {
      while (callbacks.length > 0) {
        callbacks.shift()(Module)
      }
    };
    var onPostRuns = [];
    var addOnPostRun = cb => onPostRuns.push(cb);
    var onPreRuns = [];
    var addOnPreRun = cb => onPreRuns.push(cb);
    var stackRestore = val => __emscripten_stack_restore(val);
    var stackSave = () => _emscripten_stack_get_current();
    var wasmTableMirror = [];
    var wasmTable;
    var getWasmTableEntry = funcPtr => {
      var func = wasmTableMirror[funcPtr];
      if (!func) {
        wasmTableMirror[funcPtr] = func = wasmTable.get(funcPtr)
      }
      return func
    };
    var ___call_sighandler = (fp, sig) => getWasmTableEntry(fp)(sig);
    class ExceptionInfo {
      constructor(excPtr) {
        this.excPtr = excPtr;
        this.ptr = excPtr - 24
      }
      set_type(type) {
        HEAPU32[this.ptr + 4 >> 2] = type
      }
      get_type() {
        return HEAPU32[this.ptr + 4 >> 2]
      }
      set_destructor(destructor) {
        HEAPU32[this.ptr + 8 >> 2] = destructor
      }
      get_destructor() {
        return HEAPU32[this.ptr + 8 >> 2]
      }
      set_caught(caught) {
        caught = caught ? 1 : 0;
        HEAP8[this.ptr + 12] = caught
      }
      get_caught() {
        return HEAP8[this.ptr + 12] != 0
      }
      set_rethrown(rethrown) {
        rethrown = rethrown ? 1 : 0;
        HEAP8[this.ptr + 13] = rethrown
      }
      get_rethrown() {
        return HEAP8[this.ptr + 13] != 0
      }
      init(type, destructor) {
        this.set_adjusted_ptr(0);
        this.set_type(type);
        this.set_destructor(destructor)
      }
      set_adjusted_ptr(adjustedPtr) {
        HEAPU32[this.ptr + 16 >> 2] = adjustedPtr
      }
      get_adjusted_ptr() {
        return HEAPU32[this.ptr + 16 >> 2]
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
    var initRandomFill = () => view => view.set(crypto.getRandomValues(new Uint8Array(view.byteLength)));
    var randomFill = view => {
      (randomFill = initRandomFill())(view)
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
    var TTY = undefined;
    var MEMFS = undefined;
    var preloadPlugins = [];
    var FS = undefined;

    const ECV_IO_SETUP = 0;
    const ECV_IO_DESTROY = 1;
    const ECV_IO_SUBMIT = 2;
    const ECV_IO_CANCEL = 3;
    const ECV_IO_GETEVENTS = 4;
    const ECV_SETXATTR = 5;
    const ECV_LSETXATTR = 6;
    const ECV_FSETXATTR = 7;
    const ECV_GETXATTR = 8;
    const ECV_LGETXATTR = 9;
    const ECV_FGETXATTR = 10;
    const ECV_LISTXATTR = 11;
    const ECV_LLISTXATTR = 12;
    const ECV_FLISTXATTR = 13;
    const ECV_REMOVEXATTR = 14;
    const ECV_LREMOVEXATTR = 15;
    const ECV_FREMOVEXATTR = 16;
    const ECV_GETCWD = 17;
    const ECV_LOOKUP_DCOOKIE = 18;
    const ECV_EVENTFD2 = 19;
    const ECV_EPOLL_CREATE1 = 20;
    const ECV_EPOLL_CTL = 21;
    const ECV_EPOLL_PWAIT = 22;
    const ECV_DUP = 23;
    const ECV_DUP3 = 24;
    const ECV_FCNTL = 25;
    const ECV_INOTIFY_INIT1 = 26;
    const ECV_INOTIFY_ADD_WATCH = 27;
    const ECV_INOTIFY_RM_WATCH = 28;
    const ECV_IOCTL = 29;
    const ECV_IOPRIO_SET = 30;
    const ECV_IOPRIO_GET = 31;
    const ECV_FLOCK = 32;
    const ECV_MKNODAT = 33;
    const ECV_MKDIRAT = 34;
    const ECV_UNLINKAT = 35;
    const ECV_SYMLINKAT = 36;
    const ECV_LINKAT = 37;
    const ECV_RENAMEAT = 38;
    const ECV_UMOUNT2 = 39;
    const ECV_MOUNT = 40;
    const ECV_PIVOT_ROOT = 41;
    const ECV_NFSSERVCTL = 42;
    const ECV_STATFS = 43;
    const ECV_FSTATFS = 44;
    const ECV_TRUNCATE = 45;
    const ECV_FTRUNCATE = 46;
    const ECV_FALLOCATE = 47;
    const ECV_FACCESSAT = 48;
    const ECV_CHDIR = 49;
    const ECV_FCHDIR = 50;
    const ECV_CHROOT = 51;
    const ECV_FCHMOD = 52;
    const ECV_FCHMODAT = 53;
    const ECV_FCHOWNAT = 54;
    const ECV_FCHOWN = 55;
    const ECV_OPENAT = 56;
    const ECV_CLOSE = 57;
    const ECV_VHANGUP = 58;
    const ECV_PIPE2 = 59;
    const ECV_QUOTACTL = 60;
    const ECV_GETDENTS = 61;
    const ECV_LSEEK = 62;
    const ECV_READ = 63;
    const ECV_WRITE = 64;
    const ECV_READV = 65;
    const ECV_WRITEV = 66;
    const ECV_PREAD = 67;
    const ECV_PWRITE = 68;
    const ECV_PREADV = 69;
    const ECV_PWRITEV = 70;
    const ECV_SENDFILE = 71;
    const ECV_PSELECT6 = 72;
    const ECV_PPOLL = 73;
    const ECV_SIGNALFD4 = 74;
    const ECV_VMSPLICE = 75;
    const ECV_SPLICE = 76;
    const ECV_TEE = 77;
    const ECV_READLINKAT = 78;
    const ECV_NEWFSTATAT = 79;
    const ECV_NEWFSTAT = 80;
    const ECV_SYNC = 81;
    const ECV_FSYNC = 82;
    const ECV_FDATASYNC = 83;
    const ECV_SYNC_FILE_RANGE = 84;
    const ECV_TIMERFD_CREATE = 85;
    const ECV_TIMERFD_SETTIME = 86;
    const ECV_TIMERFD_GETTIME = 87;
    const ECV_UTIMENSAT = 88;
    const ECV_ACCT = 89;
    const ECV_CAPGET = 90;
    const ECV_CAPSET = 91;
    const ECV_PERSONALITY = 92;
    const ECV_EXIT = 93;
    const ECV_EXIT_GROUP = 94;
    const ECV_WAITID = 95;
    const ECV_SET_TID_ADDRESS = 96;
    const ECV_UNSHARE = 97;
    const ECV_FUTEX = 98;
    const ECV_SET_ROBUST_LIST = 99;
    const ECV_GET_ROBUST_LIST = 100;
    const ECV_NANOSLEEP = 101;
    const ECV_GETITIMER = 102;
    const ECV_SETITIMER = 103;
    const ECV_KEXEC_LOAD = 104;
    const ECV_INIT_MODULE = 105;
    const ECV_DELETE_MODULE = 106;
    const ECV_TIMER_CREATE = 107;
    const ECV_TIMER_GETTIME = 108;
    const ECV_TIMER_GETOVERRUN = 109;
    const ECV_TIMER_SETTIME = 110;
    const ECV_TIMER_DELETE = 111;
    const ECV_CLOCK_SETTIME = 112;
    const ECV_CLOCK_GETTIME = 113;
    const ECV_CLOCK_GETRES = 114;
    const ECV_CLOCK_NANOSLEEP = 115;
    const ECV_SYSLOG = 116;
    const ECV_PTRACE = 117;
    const ECV_SCHED_SETPARAM = 118;
    const ECV_SCHED_SETSCHEDULER = 119;
    const ECV_SCHED_GETSCHEDULER = 120;
    const ECV_SCHED_GETPARAM = 121;
    const ECV_SCHED_SETAFFINITY = 122;
    const ECV_SCHED_GETAFFINITY = 123;
    const ECV_SCHED_YIELD = 124;
    const ECV_SCHED_GET_PRIORITY_MAX = 125;
    const ECV_SCHED_GET_PRIORITY_MIN = 126;
    const ECV_SCHED_RR_GET_INTERVAL = 127;
    const ECV_RESTART_SYSCALL = 128;
    const ECV_KILL = 129;
    const ECV_TKILL = 130;
    const ECV_TGKILL = 131;
    const ECV_SIGALTSTACK = 132;
    const ECV_RT_SIGSUSPEND = 133;
    const ECV_RT_SIGACTION = 134;
    const ECV_RT_SIGPROCMASK = 135;
    const ECV_RT_SIGPENDING = 136;
    const ECV_RT_SIGTIMEDWAIT = 137;
    const ECV_RT_SIGQUEUEINFO = 138;
    const ECV_RT_SIGRETURN = 139;
    const ECV_SETPRIORITY = 140;
    const ECV_GETPRIORITY = 141;
    const ECV_REBOOT = 142;
    const ECV_SETREGID = 143;
    const ECV_SETGID = 144;
    const ECV_SETREUID = 145;
    const ECV_SETUID = 146;
    const ECV_SETRESUID = 147;
    const ECV_GETRESUID = 148;
    const ECV_SETRESGID = 149;
    const ECV_GETRESGID = 150;
    const ECV_SETFSUID = 151;
    const ECV_SETFSGID = 152;
    const ECV_TIMES = 153;
    const ECV_SETPGID = 154;
    const ECV_GETPGID = 155;
    const ECV_GETSID = 156;
    const ECV_SETSID = 157;
    const ECV_GETGROUPS = 158;
    const ECV_SETGROUPS = 159;
    const ECV_UNAME = 160;
    const ECV_SETHOSTNAME = 161;
    const ECV_SETDOMAINNAME = 162;
    const ECV_GETRLIMIT = 163;
    const ECV_SETRLIMIT = 164;
    const ECV_GETRUSAGE = 165;
    const ECV_UMASK = 166;
    const ECV_PRCTL = 167;
    const ECV_GETCPU = 168;
    const ECV_GETTIMEOFDAY = 169;
    const ECV_SETTIMEOFDAY = 170;
    const ECV_ADJTIMEX = 171;
    const ECV_GETPID = 172;
    const ECV_GETPPID = 173;
    const ECV_GETUID = 174;
    const ECV_GETEUID = 175;
    const ECV_GETGID = 176;
    const ECV_GETEGID = 177;
    const ECV_GETTID = 178;
    const ECV_SYSINFO = 179;
    const ECV_MQ_OPEN = 180;
    const ECV_MQ_UNLINK = 181;
    const ECV_MQ_TIMEDSEND = 182;
    const ECV_MQ_TIMEDRECEIVE = 183;
    const ECV_MQ_NOTIFY = 184;
    const ECV_MQ_GETSETATTR = 185;
    const ECV_MSGGET = 186;
    const ECV_MSGCTL = 187;
    const ECV_MSGRCV = 188;
    const ECV_MSGSND = 189;
    const ECV_SEMGET = 190;
    const ECV_SEMCTL = 191;
    const ECV_SEMTIMEDOP = 192;
    const ECV_SEMOP = 193;
    const ECV_SHMGET = 194;
    const ECV_SHMCTL = 195;
    const ECV_SHMAT = 196;
    const ECV_SHMDT = 197;
    const ECV_SOCKET = 198;
    const ECV_SOCKETPAIR = 199;
    const ECV_BIND = 200;
    const ECV_LISTEN = 201;
    const ECV_ACCEPT = 202;
    const ECV_CONNECT = 203;
    const ECV_GETSOCKNAME = 204;
    const ECV_GETPEERNAME = 205;
    const ECV_SENDTO = 206;
    const ECV_RECVFROM = 207;
    const ECV_SETSOCKOPT = 208;
    const ECV_GETSOCKOPT = 209;
    const ECV_SHUTDOWN = 210;
    const ECV_SENDMSG = 211;
    const ECV_RECVMSG = 212;
    const ECV_READAHEAD = 213;
    const ECV_BRK = 214;
    const ECV_MUNMAP = 215;
    const ECV_MREMAP = 216;
    const ECV_ADD_KEY = 217;
    const ECV_REQUEST_KEY = 218;
    const ECV_KEYCTL = 219;
    const ECV_CLONE = 220;
    const ECV_EXECVE = 221;
    const ECV_MMAP = 222;
    const ECV_FADVISE64 = 223;
    const ECV_SWAPON = 224;
    const ECV_SWAPOFF = 225;
    const ECV_MPROTECT = 226;
    const ECV_MSYNC = 227;
    const ECV_MLOCK = 228;
    const ECV_MUNLOCK = 229;
    const ECV_MLOCKALL = 230;
    const ECV_MUNLOCKALL = 231;
    const ECV_MINCORE = 232;
    const ECV_MADVISE = 233;
    const ECV_REMAP_FILE_PAGES = 234;
    const ECV_MBIND = 235;
    const ECV_GET_MEMPOLICY = 236;
    const ECV_SET_MEMPOLICY = 237;
    const ECV_MIGRATE_PAGES = 238;
    const ECV_MOVE_PAGES = 239;
    const ECV_RT_TGSIGQUEUEINFO = 240;
    const ECV_PERF_EVENT_OPEN = 241;
    const ECV_ACCEPT4 = 242;
    const ECV_RECVMMSG = 243;
    const ECV_WAIT4 = 260;
    const ECV_PRLIMIT64 = 261;
    const ECV_FANOTIFY_INIT = 262;
    const ECV_FANOTIFY_MARK = 263;
    const ECV_NAME_TO_HANDLE_AT = 264;
    const ECV_OPEN_BY_HANDLE_AT = 265;
    const ECV_CLOCK_ADJTIME = 266;
    const ECV_SYNCFS = 267;
    const ECV_SETNS = 268;
    const ECV_SENDMMSG = 269;
    const ECV_PROCESS_VM_READV = 270;
    const ECV_PROCESS_VM_WRITEV = 271;
    const ECV_KCMP = 272;
    const ECV_FINIT_MODULE = 273;
    const ECV_SCHED_SETATTR = 274;
    const ECV_SCHED_GETATTR = 275;
    const ECV_RENAMEAT2 = 276;
    const ECV_SECCOMP = 277;
    const ECV_GETRANDOM = 278;
    const ECV_MEMFD_CREATE = 279;
    const ECV_BPF = 280;
    const ECV_EXECVEAT = 281;
    const ECV_USERFAULTFD = 282;
    const ECV_MEMBARRIER = 283;
    const ECV_MLOCK2 = 284;
    const ECV_COPY_FILE_RANGE = 285;
    const ECV_PREADV2 = 286;
    const ECV_PWRITEV2 = 287;
    const ECV_PKEY_MPROTECT = 288;
    const ECV_PKEY_ALLOC = 289;
    const ECV_PKEY_FREE = 290;
    const ECV_STATX = 291;
    const ECV_IO_PGETEVENTS = 292;
    const ECV_RSEQ = 293;
    const ECV_KEXEC_FILE_LOAD = 294;
    const ECV_PIDFD_SEND_SIGNAL = 424;
    const ECV_IO_URING_SETUP = 425;
    const ECV_IO_URING_ENTER = 426;
    const ECV_IO_URING_REGISTER = 427;
    const ECV_OPEN_TREE = 428;
    const ECV_MOVE_MOUNT = 429;
    const ECV_FSOPEN = 430;
    const ECV_FSCONFIG = 431;
    const ECV_FSMOUNT = 432;
    const ECV_FSPICK = 433;
    const ECV_PIDFD_OPEN = 434;
    const ECV_CLONE3 = 435;
    const ECV_CLOSE_RANGE = 436;
    const ECV_OPENAT2 = 437;
    const ECV_PIDFD_GETFD = 438;
    const ECV_FACCESSAT2 = 439;
    const ECV_PROCESS_MADVISE = 440;
    const ECV_EPOLL_PWAIT2 = 441;
    const ECV_MOUNT_SETATTR = 442;
    const ECV_QUOTACTL_FD = 443;
    const ECV_LANDLOCK_CREATE_RULESET = 444;
    const ECV_LANDLOCK_ADD_RULE = 445;
    const ECV_LANDLOCK_RESTRICT_SELF = 446;
    const ECV_MEMFD_SECRET = 447;
    const ECV_PROCESS_MRELEASE = 448;
    const ECV_FUTEX_WAITV = 449;

    // macro specified to the emscripten runtime
    // const ECV_ENVIRON_GET = 1001;
    // const ECV_ENVIRON_SIZES_GET = 1002;

    function ___syscall_chdir(path) {
      return ecvProxySyscallJs(ECV_CHDIR, path);
    }

    function ___syscall_dup(fd) {
      return ecvProxySyscallJs(ECV_DUP, fd);
    }

    function ___syscall_dup3(fd, newfd, flags) {
      return ecvProxySyscallJs(ECV_DUP3, fd, newfd, flags);
    }

    function ___syscall_faccessat(dirfd, path, amode, flags) {
      return ecvProxySyscallJs(ECV_FACCESSAT, dirfd, path, amode, flags);
    }

    function ___syscall_fcntl64(fd, cmd, varargs) {
      return ecvProxySyscallJs(ECV_FCNTL, fd, cmd, varargs);
    }

    function ___syscall_fstat64(fd, buf) {
      return ecvProxySyscallJs(ECV_NEWFSTAT, fd, buf);
    }
    var INT53_MAX = 9007199254740992;
    var INT53_MIN = -9007199254740992;
    var bigintToI53Checked = num => num < INT53_MIN || num > INT53_MAX ? NaN : Number(num);

    function ___syscall_ftruncate64(fd, length) {
      return ecvProxySyscallJs(ECV_FTRUNCATE, fd, length);
    }
    var stringToUTF8 = (str, outPtr, maxBytesToWrite) => stringToUTF8Array(str, HEAPU8, outPtr, maxBytesToWrite);

    function ___syscall_getcwd(buf, size) {
      return ecvProxySyscallJs(ECV_GETCWD, buf, size);
    }

    function ___syscall_getdents64(fd, dirp, count) {
      return ecvProxySyscallJs(ECV_GETDENTS, fd, dirp, count);
    }

    function ___syscall_ioctl(fd, op, varargs) {
      return ecvProxySyscallJs(ECV_IOCTL, fd, op, varargs);
    }

    function ___syscall_lstat64(path, buf) {
      throw "___syscall_lstat64 is not implemented.";
    }

    function ___syscall_mkdirat(dirfd, path, mode) {
      return ecvProxySyscallJs(ECV_MKDIRAT, dirfd, path, mode);
    }

    function ___syscall_newfstatat(dirfd, path, buf, flags) {
      return ecvProxySyscallJs(ECV_NEWFSTATAT, dirfd, path, buf, flags);
    }

    function ___syscall_openat(dirfd, path, flags, varargs) {
      return ecvProxySyscallJs(ECV_OPENAT, dirfd, path, flags, varargs);
    }

    function ___syscall_poll(fds, nfds, timeout) {
      return ecvProxySyscallJs(ECV_PPOLL, fds, nfds, timeout);
    }

    function ___syscall_readlinkat(dirfd, path, buf, bufsize) {
      return ecvProxySyscallJs(ECV_READLINKAT, dirfd, path, buf, bufsize);
    }

    function ___syscall_stat64(path, buf) {
      return ecvProxySyscallJs(ECV_STATX, path, buf);
    }

    function ___syscall_statfs64(path, size, buf) {
      return ecvProxySyscallJs(ECV_STATFS, path, size, buf);
    }

    function ___syscall_truncate64(path, length) {
      return ecvProxySyscallJs(ECV_TRUNCATE, path, length);
    }

    function ___syscall_unlinkat(dirfd, path, flags) {
      return ecvProxySyscallJs(ECV_UNLINKAT, dirfd, path, flags);
    }
    var readI53FromI64 = ptr => HEAPU32[ptr >> 2] + HEAP32[ptr + 4 >> 2] * 4294967296;

    function ___syscall_utimensat(dirfd, path, times, flags) {
      return ecvProxySyscallJs(ECV_UTIMENSAT, dirfd, path, times, flags);
    }
    var __abort_js = () => abort("");
    var runtimeKeepaliveCounter = 0;
    var __emscripten_runtime_keepalive_clear = () => {
      noExitRuntime = false;
      runtimeKeepaliveCounter = 0
    };
    var __tzset_js = (timezone, daylight, std_name, dst_name) => {
      var currentYear = (new Date).getFullYear();
      var winter = new Date(currentYear, 0, 1);
      var summer = new Date(currentYear, 6, 1);
      var winterOffset = winter.getTimezoneOffset();
      var summerOffset = summer.getTimezoneOffset();
      var stdTimezoneOffset = Math.max(winterOffset, summerOffset);
      HEAPU32[timezone >> 2] = stdTimezoneOffset * 60;
      HEAP32[daylight >> 2] = Number(winterOffset != summerOffset);
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
    var _emscripten_get_now = () => performance.now();
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
      HEAP64[ptime >> 3] = BigInt(nsec);
      return 0
    }
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
      var oldSize = HEAPU8.length;
      requestedSize >>>= 0;
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
    var ENV = {};
    var getExecutableName = () => thisProgram || "./hello.wasm";
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
    var _environ_get = (__environ, environ_buf) => {
      var bufSize = 0;
      var envp = 0;
      for (var string of getEnvStrings()) {
        var ptr = environ_buf + bufSize;
        HEAPU32[__environ + envp >> 2] = ptr;
        bufSize += stringToUTF8(string, ptr, Infinity) + 1;
        envp += 4
      }
      return 0
    };
    var _environ_sizes_get = (penviron_count, penviron_buf_size) => {
      var strings = getEnvStrings();
      HEAPU32[penviron_count >> 2] = strings.length;
      var bufSize = 0;
      for (var string of strings) {
        bufSize += lengthBytesUTF8(string) + 1
      }
      HEAPU32[penviron_buf_size >> 2] = bufSize;
      return 0
    };
    var _proc_exit = code => {
      return ecvProxySyscallJs(ECV_EXIT, code);
    };
    var exitJS = (status, implicit) => {
      EXITSTATUS = status;
      _proc_exit(status)
    };
    var _exit = exitJS;

    function _fd_close(fd) {
      return ecvProxySyscallJs(ECV_CLOSE, fd);
    }

    function _fd_read(fd, iov, iovcnt, pnum) {
      return ecvProxySyscallJs(ECV_READ, fd, iov, iovcnt, pnum);
    }

    function _fd_seek(fd, offset, whence, newOffset) {
      return ecvProxySyscallJs(ECV_LSEEK, fd, offset, whence, newOffset);
    }

    function _fd_sync(fd) {
      return ecvProxySyscallJs(ECV_SYNC, fd);
    }

    function _fd_write(fd, iov, iovcnt, pnum) {
      return ecvProxySyscallJs(ECV_WRITE, fd, iov, iovcnt, pnum);
    }

    function _random_get(buffer, size) {
      try {
        randomFill(HEAPU8.subarray(buffer, buffer + size));
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }
    var handleException = e => {
      if (e instanceof ExitStatus || e == "unwind") {
        return EXITSTATUS
      }
      quit_(1, e)
    };
    var stackAlloc = sz => __emscripten_stack_alloc(sz);
    var stringToUTF8OnStack = str => {
      var size = lengthBytesUTF8(str) + 1;
      var ret = stackAlloc(size);
      stringToUTF8(str, ret, size);
      return ret
    };
    // MEMFS.doesNotExistError = new FS.ErrnoError(44);
    // MEMFS.doesNotExistError.stack = "<generic error, no stack>";
    {
      if (Module["noExitRuntime"]) noExitRuntime = Module["noExitRuntime"];
      if (Module["preloadPlugins"]) preloadPlugins = Module["preloadPlugins"];
      if (Module["print"]) out = Module["print"];
      if (Module["printErr"]) err = Module["printErr"];
      if (Module["wasmBinary"]) wasmBinary = Module["wasmBinary"];
      if (Module["arguments"]) arguments_ = Module["arguments"];
      if (Module["thisProgram"]) thisProgram = Module["thisProgram"]
    }

    var wasmImports;

    var __emscripten_init_main_thread_js = tb => {
      console.log("[call] __emscripten_init_main_thread_js.");
    };
    var __emscripten_notify_mailbox_postmessage = (targetThread, currThreadId) => {
      console.log("[call] __emscripten_nofity_mailbox_postmessage.");
    }
    var __emscripten_receive_on_main_thread_js = (funcIndex, emAsmAddr, callingThread, numCallArgs, args) => {
      console.log("[call] __emscripten_receive_on_main_thread_js.");
    }
    var __emscripten_runtime_keepalive_clear = () => {
      console.log("[call] __emscripten_runtime_keepalive_clear.");
    }
    var __emscripten_thread_cleanup = thread => {
      console.log("[call] __emscripten_thread_cleanup.");
    }
    var __emscripten_thread_mailbox_await = pthread_ptr => {
      console.log("[call] __emscripten_thread_mailbox_await.");
    }
    var __emscripten_thread_set_strongref = thread => {
      console.log("[call] __emscripten_thread_set_strongref.");
    };
    var _emscripten_check_blocking_allowed = () => {
      console.log("[call] _emscripten_check_blocking_allowed.");
    };
    var _emscripten_exit_with_live_runtime = () => {
      console.log("[call] _emscripten_exit_with_live_runtime.");
    };

    function assignWasmImports() {
      wasmImports = {
        z: ___call_sighandler,
        i: ___cxa_throw,
        D: ___syscall_chdir,
        m: ___syscall_dup,
        l: ___syscall_dup3,
        j: ___syscall_faccessat,
        c: ___syscall_fcntl64,
        U: ___syscall_fstat64,
        P: ___syscall_ftruncate64,
        N: ___syscall_getcwd,
        M: ___syscall_getdents64,
        g: ___syscall_ioctl,
        R: ___syscall_lstat64,
        H: ___syscall_mkdirat,
        S: ___syscall_newfstatat,
        G: ___syscall_openat,
        F: ___syscall_poll,
        y: ___syscall_readlinkat,
        T: ___syscall_stat64,
        x: ___syscall_statfs64,
        u: ___syscall_truncate64,
        t: ___syscall_unlinkat,
        s: ___syscall_utimensat,
        O: __abort_js,
        K: __emscripten_init_main_thread_js,
        w: __emscripten_notify_mailbox_postmessage,
        E: __emscripten_receive_on_main_thread_js,
        B: __emscripten_runtime_keepalive_clear,
        n: __emscripten_thread_cleanup,
        J: __emscripten_thread_mailbox_await,
        W: __emscripten_thread_set_strongref,
        o: __tzset_js,
        v: _clock_time_get,
        C: _emscripten_check_blocking_allowed,
        k: _emscripten_date_now,
        V: _emscripten_exit_with_live_runtime,
        b: _emscripten_get_now,
        r: _emscripten_resize_heap,
        p: _environ_get,
        q: _environ_sizes_get,
        f: _exit,
        e: _fd_close,
        h: _fd_read,
        I: _fd_seek,
        Q: _fd_sync,
        d: _fd_write,
        a: wasmMemory,
        A: _proc_exit,
        L: _random_get
      }
    }

    var wasmExports, _main, _pthread_self, __emscripten_thread_init, __emscripten_thread_crashed, __emscripten_run_on_main_thread_js, __emscripten_thread_free_data,
      __emscripten_thread_exit, __emscripten_check_mailbox, _emscripten_stack_set_limits, __emscripten_stack_restore, __emscripten_stack_alloc, _emscripten_stack_get_current;

    async function startWorker() {

      // init Wasm module
      wasmExports = await createWasm();
      _main = Module["_main"] = (a0, a1) => (_main = Module["_main"] = wasmExports["jc"])(a0, a1);
      // _pthread_self = () => (_pthread_self = wasmExports["zc"])();
      // __emscripten_thread_init = (a0, a1, a2, a3, a4, a5) => (__emscripten_thread_init = wasmExports["Ac"])(a0, a1, a2, a3, a4, a5);
      // __emscripten_thread_crashed = () => (__emscripten_thread_crashed = wasmExports["Bc"])();
      // __emscripten_run_on_main_thread_js = (a0, a1, a2, a3, a4) => (__emscripten_run_on_main_thread_js = wasmExports["Cc"])(a0, a1, a2, a3, a4);
      // __emscripten_thread_free_data = a0 => (__emscripten_thread_free_data = wasmExports["Dc"])(a0);
      // __emscripten_thread_exit = a0 => (__emscripten_thread_exit = wasmExports["Ec"])(a0);
      // __emscripten_check_mailbox = () => (__emscripten_check_mailbox = wasmExports["Fc"])();
      // _emscripten_stack_set_limits = (a0, a1) => (_emscripten_stack_set_limits = wasmExports["Gc"])(a0, a1);
      __emscripten_stack_restore = a0 => (__emscripten_stack_restore = wasmExports["Hc"])(a0);
      __emscripten_stack_alloc = a0 => (__emscripten_stack_alloc = wasmExports["Ic"])(a0);
      _emscripten_stack_get_current = () => (_emscripten_stack_get_current = wasmExports["Jc"])();

      // run
      preInit();
      run();
      moduleRtn = readyPromise;
    }

    // var ___wasm_call_ctors = wasmExports["P"];
    // var ___remill_flag_computation_overflow = Module["___remill_flag_computation_overflow"] = wasmExports["Q"];
    // var ___remill_barrier_store_store = Module["___remill_barrier_store_store"] = wasmExports["R"];
    // var ___remill_barrier_load_store = Module["___remill_barrier_load_store"] = wasmExports["S"];
    // var ___remill_syscall_tranpoline_call = Module["___remill_syscall_tranpoline_call"] = wasmExports["T"];
    // var ___remill_read_memory_8 = Module["___remill_read_memory_8"] = wasmExports["U"];
    // var ___remill_read_memory_16 = Module["___remill_read_memory_16"] = wasmExports["V"];
    // var ___remill_read_memory_32 = Module["___remill_read_memory_32"] = wasmExports["W"];
    // var ___remill_read_memory_64 = Module["___remill_read_memory_64"] = wasmExports["X"];
    // var ___remill_read_memory_128 = Module["___remill_read_memory_128"] = wasmExports["Y"];
    // var ___remill_write_memory_8 = Module["___remill_write_memory_8"] = wasmExports["Z"];
    // var ___remill_write_memory_16 = Module["___remill_write_memory_16"] = wasmExports["_"];
    // var ___remill_write_memory_32 = Module["___remill_write_memory_32"] = wasmExports["$"];
    // var ___remill_write_memory_64 = Module["___remill_write_memory_64"] = wasmExports["aa"];
    // var ___remill_write_memory_128 = Module["___remill_write_memory_128"] = wasmExports["ba"];
    // var ___remill_read_memory_f32 = Module["___remill_read_memory_f32"] = wasmExports["ca"];
    // var ___remill_read_memory_f64 = Module["___remill_read_memory_f64"] = wasmExports["da"];
    // var ___remill_read_memory_f128 = Module["___remill_read_memory_f128"] = wasmExports["ea"];
    // var ___remill_write_memory_f32 = Module["___remill_write_memory_f32"] = wasmExports["fa"];
    // var ___remill_write_memory_f64 = Module["___remill_write_memory_f64"] = wasmExports["ga"];
    // var ___remill_write_memory_f128 = Module["___remill_write_memory_f128"] = wasmExports["ha"];
    // var ___remill_barrier_load_load = Module["___remill_barrier_load_load"] = wasmExports["ia"];
    // var ___remill_barrier_store_load = Module["___remill_barrier_store_load"] = wasmExports["ja"];
    // var ___remill_atomic_begin = Module["___remill_atomic_begin"] = wasmExports["ka"];
    // var ___remill_atomic_end = Module["___remill_atomic_end"] = wasmExports["la"];
    // var ___remill_delay_slot_begin = Module["___remill_delay_slot_begin"] = wasmExports["ma"];
    // var ___remill_delay_slot_end = Module["___remill_delay_slot_end"] = wasmExports["na"];
    // var ___remill_compare_exchange_memory_8 = Module["___remill_compare_exchange_memory_8"] = wasmExports["oa"];
    // var ___remill_compare_exchange_memory_16 = Module["___remill_compare_exchange_memory_16"] = wasmExports["pa"];
    // var ___remill_compare_exchange_memory_32 = Module["___remill_compare_exchange_memory_32"] = wasmExports["qa"];
    // var ___remill_compare_exchange_memory_64 = Module["___remill_compare_exchange_memory_64"] = wasmExports["ra"];
    // var ___remill_fetch_and_add_8 = Module["___remill_fetch_and_add_8"] = wasmExports["sa"];
    // var ___remill_fetch_and_add_16 = Module["___remill_fetch_and_add_16"] = wasmExports["ta"];
    // var ___remill_fetch_and_add_32 = Module["___remill_fetch_and_add_32"] = wasmExports["ua"];
    // var ___remill_fetch_and_add_64 = Module["___remill_fetch_and_add_64"] = wasmExports["va"];
    // var ___remill_fetch_and_sub_8 = Module["___remill_fetch_and_sub_8"] = wasmExports["wa"];
    // var ___remill_fetch_and_sub_16 = Module["___remill_fetch_and_sub_16"] = wasmExports["xa"];
    // var ___remill_fetch_and_sub_32 = Module["___remill_fetch_and_sub_32"] = wasmExports["ya"];
    // var ___remill_fetch_and_sub_64 = Module["___remill_fetch_and_sub_64"] = wasmExports["za"];
    // var ___remill_fetch_and_or_8 = Module["___remill_fetch_and_or_8"] = wasmExports["Aa"];
    // var ___remill_fetch_and_or_16 = Module["___remill_fetch_and_or_16"] = wasmExports["Ba"];
    // var ___remill_fetch_and_or_32 = Module["___remill_fetch_and_or_32"] = wasmExports["Ca"];
    // var ___remill_fetch_and_or_64 = Module["___remill_fetch_and_or_64"] = wasmExports["Da"];
    // var ___remill_fetch_and_and_8 = Module["___remill_fetch_and_and_8"] = wasmExports["Ea"];
    // var ___remill_fetch_and_and_16 = Module["___remill_fetch_and_and_16"] = wasmExports["Fa"];
    // var ___remill_fetch_and_and_32 = Module["___remill_fetch_and_and_32"] = wasmExports["Ga"];
    // var ___remill_fetch_and_and_64 = Module["___remill_fetch_and_and_64"] = wasmExports["Ha"];
    // var ___remill_fetch_and_xor_8 = Module["___remill_fetch_and_xor_8"] = wasmExports["Ia"];
    // var ___remill_fetch_and_xor_16 = Module["___remill_fetch_and_xor_16"] = wasmExports["Ja"];
    // var ___remill_fetch_and_xor_32 = Module["___remill_fetch_and_xor_32"] = wasmExports["Ka"];
    // var ___remill_fetch_and_xor_64 = Module["___remill_fetch_and_xor_64"] = wasmExports["La"];
    // var ___remill_fpu_exception_test_and_clear = Module["___remill_fpu_exception_test_and_clear"] = wasmExports["Ma"];
    // var ___remill_error = Module["___remill_error"] = wasmExports["Na"];
    // var ___remill_function_call = Module["___remill_function_call"] = wasmExports["Oa"];
    // var ___remill_function_return = Module["___remill_function_return"] = wasmExports["Pa"];
    // var ___remill_jump = Module["___remill_jump"] = wasmExports["Qa"];
    // var ___remill_missing_block = Module["___remill_missing_block"] = wasmExports["Ra"];
    // var __ecv_func_epilogue = Module["__ecv_func_epilogue"] = wasmExports["Sa"];
    // var ___remill_async_hyper_call = Module["___remill_async_hyper_call"] = wasmExports["Ta"];
    // var ___remill_undefined_8 = Module["___remill_undefined_8"] = wasmExports["Ua"];
    // var ___remill_undefined_16 = Module["___remill_undefined_16"] = wasmExports["Va"];
    // var ___remill_undefined_32 = Module["___remill_undefined_32"] = wasmExports["Wa"];
    // var ___remill_undefined_64 = Module["___remill_undefined_64"] = wasmExports["Xa"];
    // var ___remill_undefined_f32 = Module["___remill_undefined_f32"] = wasmExports["Ya"];
    // var ___remill_undefined_f64 = Module["___remill_undefined_f64"] = wasmExports["Za"];
    // var ___remill_flag_computation_zero = Module["___remill_flag_computation_zero"] = wasmExports["_a"];
    // var ___remill_flag_computation_sign = Module["___remill_flag_computation_sign"] = wasmExports["$a"];
    // var ___remill_flag_computation_carry = Module["___remill_flag_computation_carry"] = wasmExports["ab"];
    // var ___remill_compare_sle = Module["___remill_compare_sle"] = wasmExports["bb"];
    // var ___remill_compare_slt = Module["___remill_compare_slt"] = wasmExports["cb"];
    // var ___remill_compare_sgt = Module["___remill_compare_sgt"] = wasmExports["db"];
    // var ___remill_compare_sge = Module["___remill_compare_sge"] = wasmExports["eb"];
    // var ___remill_compare_eq = Module["___remill_compare_eq"] = wasmExports["fb"];
    // var ___remill_compare_neq = Module["___remill_compare_neq"] = wasmExports["gb"];
    // var ___remill_compare_ugt = Module["___remill_compare_ugt"] = wasmExports["hb"];
    // var ___remill_compare_uge = Module["___remill_compare_uge"] = wasmExports["ib"];
    // var ___remill_compare_ult = Module["___remill_compare_ult"] = wasmExports["jb"];
    // var ___remill_compare_ule = Module["___remill_compare_ule"] = wasmExports["kb"];
    // var ___remill_x86_set_segment_es = Module["___remill_x86_set_segment_es"] = wasmExports["lb"];
    // var ___remill_x86_set_segment_ss = Module["___remill_x86_set_segment_ss"] = wasmExports["mb"];
    // var ___remill_x86_set_segment_ds = Module["___remill_x86_set_segment_ds"] = wasmExports["nb"];
    // var ___remill_x86_set_segment_fs = Module["___remill_x86_set_segment_fs"] = wasmExports["ob"];
    // var ___remill_x86_set_segment_gs = Module["___remill_x86_set_segment_gs"] = wasmExports["pb"];
    // var ___remill_x86_set_debug_reg = Module["___remill_x86_set_debug_reg"] = wasmExports["qb"];
    // var ___remill_x86_set_control_reg_0 = Module["___remill_x86_set_control_reg_0"] = wasmExports["rb"];
    // var ___remill_x86_set_control_reg_1 = Module["___remill_x86_set_control_reg_1"] = wasmExports["sb"];
    // var ___remill_x86_set_control_reg_2 = Module["___remill_x86_set_control_reg_2"] = wasmExports["tb"];
    // var ___remill_x86_set_control_reg_3 = Module["___remill_x86_set_control_reg_3"] = wasmExports["ub"];
    // var ___remill_x86_set_control_reg_4 = Module["___remill_x86_set_control_reg_4"] = wasmExports["vb"];
    // var ___remill_amd64_set_debug_reg = Module["___remill_amd64_set_debug_reg"] = wasmExports["wb"];
    // var ___remill_amd64_set_control_reg_0 = Module["___remill_amd64_set_control_reg_0"] = wasmExports["xb"];
    // var ___remill_amd64_set_control_reg_1 = Module["___remill_amd64_set_control_reg_1"] = wasmExports["yb"];
    // var ___remill_amd64_set_control_reg_2 = Module["___remill_amd64_set_control_reg_2"] = wasmExports["zb"];
    // var ___remill_amd64_set_control_reg_3 = Module["___remill_amd64_set_control_reg_3"] = wasmExports["Ab"];
    // var ___remill_amd64_set_control_reg_4 = Module["___remill_amd64_set_control_reg_4"] = wasmExports["Bb"];
    // var ___remill_amd64_set_control_reg_8 = Module["___remill_amd64_set_control_reg_8"] = wasmExports["Cb"];
    // var ___remill_aarch64_emulate_instruction = Module["___remill_aarch64_emulate_instruction"] = wasmExports["Db"];
    // var ___remill_aarch32_emulate_instruction = Module["___remill_aarch32_emulate_instruction"] = wasmExports["Eb"];
    // var ___remill_aarch32_check_not_el2 = Module["___remill_aarch32_check_not_el2"] = wasmExports["Fb"];
    // var ___remill_sparc_set_asi_register = Module["___remill_sparc_set_asi_register"] = wasmExports["Gb"];
    // var ___remill_sparc_unimplemented_instruction = Module["___remill_sparc_unimplemented_instruction"] = wasmExports["Hb"];
    // var ___remill_sparc_unhandled_dcti = Module["___remill_sparc_unhandled_dcti"] = wasmExports["Ib"];
    // var ___remill_sparc_window_underflow = Module["___remill_sparc_window_underflow"] = wasmExports["Jb"];
    // var ___remill_sparc_trap_cond_a = Module["___remill_sparc_trap_cond_a"] = wasmExports["Kb"];
    // var ___remill_sparc_trap_cond_n = Module["___remill_sparc_trap_cond_n"] = wasmExports["Lb"];
    // var ___remill_sparc_trap_cond_ne = Module["___remill_sparc_trap_cond_ne"] = wasmExports["Mb"];
    // var ___remill_sparc_trap_cond_e = Module["___remill_sparc_trap_cond_e"] = wasmExports["Nb"];
    // var ___remill_sparc_trap_cond_g = Module["___remill_sparc_trap_cond_g"] = wasmExports["Ob"];
    // var ___remill_sparc_trap_cond_le = Module["___remill_sparc_trap_cond_le"] = wasmExports["Pb"];
    // var ___remill_sparc_trap_cond_ge = Module["___remill_sparc_trap_cond_ge"] = wasmExports["Qb"];
    // var ___remill_sparc_trap_cond_l = Module["___remill_sparc_trap_cond_l"] = wasmExports["Rb"];
    // var ___remill_sparc_trap_cond_gu = Module["___remill_sparc_trap_cond_gu"] = wasmExports["Sb"];
    // var ___remill_sparc_trap_cond_leu = Module["___remill_sparc_trap_cond_leu"] = wasmExports["Tb"];
    // var ___remill_sparc_trap_cond_cc = Module["___remill_sparc_trap_cond_cc"] = wasmExports["Ub"];
    // var ___remill_sparc_trap_cond_cs = Module["___remill_sparc_trap_cond_cs"] = wasmExports["Vb"];
    // var ___remill_sparc_trap_cond_pos = Module["___remill_sparc_trap_cond_pos"] = wasmExports["Wb"];
    // var ___remill_sparc_trap_cond_neg = Module["___remill_sparc_trap_cond_neg"] = wasmExports["Xb"];
    // var ___remill_sparc_trap_cond_vc = Module["___remill_sparc_trap_cond_vc"] = wasmExports["Yb"];
    // var ___remill_sparc_trap_cond_vs = Module["___remill_sparc_trap_cond_vs"] = wasmExports["Zb"];
    // var ___remill_sparc32_emulate_instruction = Module["___remill_sparc32_emulate_instruction"] = wasmExports["_b"];
    // var ___remill_sparc64_emulate_instruction = Module["___remill_sparc64_emulate_instruction"] = wasmExports["$b"];
    // var _main = Module["_main"] = wasmExports["bc"];
    // var ___remill_undefined_f128 = Module["___remill_undefined_f128"] = wasmExports["cc"];
    // var ___remill_compare_exchange_memory_128 = Module["___remill_compare_exchange_memory_128"] = wasmExports["dc"];
    // var ___remill_fetch_and_nand_8 = Module["___remill_fetch_and_nand_8"] = wasmExports["ec"];
    // var ___remill_fetch_and_nand_16 = Module["___remill_fetch_and_nand_16"] = wasmExports["fc"];
    // var ___remill_fetch_and_nand_32 = Module["___remill_fetch_and_nand_32"] = wasmExports["gc"];
    // var ___remill_fetch_and_nand_64 = Module["___remill_fetch_and_nand_64"] = wasmExports["hc"];
    // var ___remill_read_io_port_8 = Module["___remill_read_io_port_8"] = wasmExports["ic"];
    // var ___remill_read_io_port_16 = Module["___remill_read_io_port_16"] = wasmExports["jc"];
    // var ___remill_read_io_port_32 = Module["___remill_read_io_port_32"] = wasmExports["kc"];
    // var ___remill_write_io_port_8 = Module["___remill_write_io_port_8"] = wasmExports["lc"];
    // var ___remill_write_io_port_16 = Module["___remill_write_io_port_16"] = wasmExports["mc"];
    // var ___remill_write_io_port_32 = Module["___remill_write_io_port_32"] = wasmExports["nc"];
    // var ___remill_ppc_emulate_instruction = Module["___remill_ppc_emulate_instruction"] = wasmExports["oc"];
    // var ___remill_ppc_syscall = Module["___remill_ppc_syscall"] = wasmExports["pc"];
    // var __emscripten_stack_alloc = wasmExports["qc"];

    function callMain(args = []) {
      var entryFunction = _main;
      args.unshift(thisProgram);
      var argc = args.length;
      var argv = stackAlloc((argc + 1) * 4);
      var argv_ptr = argv;
      args.forEach(arg => {
        HEAPU32[argv_ptr >> 2] = stringToUTF8OnStack(arg);
        argv_ptr += 4
      });
      HEAPU32[argv_ptr >> 2] = 0;
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
      preRun();
      if (runDependencies > 0) {
        dependenciesFulfilled = run;
        return
      }

      if (!wasmMemory) {
        throw "wasmMemory has not been intialized yet (at process worker)."
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

    return moduleRtn;
  });
})();
export default Module;

Module();