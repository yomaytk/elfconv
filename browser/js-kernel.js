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
    var initProcessJsPath = Module["initProgram"] ? Module["initProgram"].slice(0, -5) + ".js" : "process-worker.js";
    var quit_ = (status, toThrow) => {
      throw toThrow
    };
    var _scriptName = import.meta.url;
    var INITIAL_MEMORY_SIZE = 16777216;
    var userBinList = Module["executables"];

    var initProcessInitialized = false;
    var initWasmDoneNum = 0;
    var tEcvPid = 42;  // used for multi processes FS.
    var ecvPidCounter = 42;
    var gWasmMemory;
    var SysFuncMap = new Map();
    var processes = new Map();
    var FIFO_AtomicBuf = new SharedArrayBuffer(4 * 4096); // FD: 0~4096

    const prLingOffset = 4;
    const childProcessMax = 20;

    // Linux macro
    const __FD_SETSIZE = 1024;
    const __KERNEL_FD_SETMAXID = 16;

    // Basic access modes (from asm-generic/fcntl.h)
    const O_RDONLY = 0x0;        // 0       : Open for read-only
    const O_WRONLY = 0x1;        // 1       : Open for write-only
    const O_RDWR = 0x2;        // 2       : Open for read/write

    // Open flags (from asm-generic/fcntl.h)
    const O_CREAT = 0o100;      // 64      : Create file if it does not exist
    const O_EXCL = 0o200;      // 128     : Error if O_CREAT and file exists
    const O_NOCTTY = 0o400;      // 256     : Do not assign controlling terminal
    const O_TRUNC = 0o1000;     // 512     : Truncate file to zero length
    const O_APPEND = 0o2000;     // 1024    : Append writes to end of file
    const O_NONBLOCK = 0o4000;     // 2048    : Non-blocking I/O
    const O_DSYNC = 0o10000;    // 4096    : Synchronized data-only writes
    const O_SYNC = 0o4010000;  // 1052672 : POSIX O_SYNC (data+metadata sync)

    // close-on-exec
    const O_CLOEXEC = 0o2000000;  // 524288  : Set FD_CLOEXEC on open
    const FD_CLOEXEC = 1; // close-on-exec bit on fd_flags.

    // Additional Linux open flags
    const O_DIRECTORY = 0o200000;   // 65536   : Fail if path is not a directory
    const O_NOFOLLOW = 0o400000;   // 131072  : Do not follow symbolic links

    // File type bits (st_mode) — from stat.h
    const S_IFMT = 0o170000;      // 61440   : Bit mask for file type
    const S_IFREG = 0o100000;      // 32768   : Regular file
    const S_IFDIR = 0o040000;      // 16384   : Directory
    const S_IFIFO = 0o010000;      // 4096    : FIFO / pipe
    const S_IFCHR = 0o020000;      // 8192    : Character device
    const S_IFBLK = 0o060000;      // 24576   : Block device
    const S_IFLNK = 0o120000;      // 40960   : Symbolic link

    // Permission bits (from <sys/stat.h>)
    // User (owner) permissions
    const S_IRWXU = 0o700;   // 448  : user  (owner) read, write, execute
    const S_IRUSR = 0o400;   // 256  : user  read
    const S_IWUSR = 0o200;   // 128  : user  write
    const S_IXUSR = 0o100;   // 64   : user  execute

    // Group permissions
    const S_IRWXG = 0o070;   // 56   : group read, write, execute
    const S_IRGRP = 0o040;   // 32   : group read
    const S_IWGRP = 0o020;   // 16   : group write
    const S_IXGRP = 0o010;   // 8    : group execute

    // Others permissions
    const S_IRWXO = 0o007;   // 7    : others read, write, execute
    const S_IROTH = 0o004;   // 4    : others read
    const S_IWOTH = 0o002;   // 2    : others write
    const S_IXOTH = 0o001;   // 1    : others execute

    // poll
    const POLLIN = 0x1;   // Data available to read
    const POLLOUT = 0x2;   // Writing will not block
    const POLLPRI = 0x4;   // Urgent data / high-priority data available
    const POLLERR = 0x8;   // Error condition on FD (always reported)
    const POLLHUP = 0x10;  // Hang up (peer closed / no writers)

    // Pipe
    const PIPE_MAX_SZ = 65536;

    function getNewEcvPid() {
      return ecvPidCounter++;
    }

    function growMemViews(wasmMemory_) {
      if (wasmMemory_.buffer != HEAP8.buffer) {
        updateMemoryViews(wasmMemory_);
      }
    }

    function updateMemoryViews(wasmMemory_) {
      var b = wasmMemory_.buffer;
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

    var readAsync, readBinary;
    if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
      try {
        const _ = new URL(".", _scriptName).href
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
    var ABORT = false;
    var EXITSTATUS;
    var HEAP8, HEAPU8, HEAP16, HEAPU16, HEAP32, HEAPU32, HEAPF32, HEAP64, HEAPU64, HEAPF64;

    var WORKER_MGR = {
      wasmModules: new Map(),
      workerInfoPool: [],
      prWorkerPoolCapacity: 20,
      dupWorkerNum: 3,
      S_STOP: 0,
      S_RUNNING: 1,
      newProcessMemory(memSize) { // Wasm initial memory size (INITIAL_MEMORY_SIZE): 16MB
        return new WebAssembly.Memory({
          initial: memSize / 65536,
          maximum: 4096,
          shared: true
        });
      },
      init(userBinSet) {
        for (let userBinPath of userBinSet) {
          // We create the 3 workers for the every executable binary.
          // When we try 4 or more workers, it will take a bit time to start the target program.
          for (let i = 0; i < this.dupWorkerNum; i++) {
            let jsPath = userBinPath + ".js";
            let wasmPath = userBinPath + ".wasm";
            let id = this.workerInfoPool.length;
            let memory = this.newProcessMemory(INITIAL_MEMORY_SIZE);
            let worker = new Worker(new URL(jsPath, import.meta.url), {
              type: "module",
              name: `${jsPath}-worker-${id}`,
            });
            let wasmModule = this.wasmModules.get(wasmPath);
            if (!wasmModule) {
              throw new Error(`wasm module '${wasmPath}' has not been initialzed yet (at WORKER_MGR.init).`);
            }
            this.setInitialMsgHandling(worker);
            this.workerInfoPool.push({
              id: id,
              status: this.S_STOP,
              jsPath: jsPath,
              memory: memory,
              worker: worker,
              module: wasmModule,
            });
            worker.postMessage({
              cmd: "initWasm",
              workerId: id,
              wasmProgram: wasmPath,
              wasmMemory: memory,
              wasmModule: wasmModule,
            });
          }
        }
      },
      getAvailableWorkerInfo(jsPath) {
        let workerInfo = null;
        // find the existing worker.
        for (let prWorker of this.workerInfoPool) {
          if (prWorker.jsPath === jsPath && prWorker.status === this.S_STOP) {
            prWorker.status = this.S_RUNNING;
            workerInfo = prWorker;
            break;
          }
        }
        // create the new worker.
        if (!workerInfo) {
          let id = this.workerInfoPool.length;
          let memory = this.newProcessMemory(INITIAL_MEMORY_SIZE);
          let wasmPath = jsPath.slice(0, -3) + ".wasm";
          let worker = new Worker(new URL(jsPath, import.meta.url), {
            type: "module",
            name: `${jsPath}-worker-${id}`,
          });
          let wasmModule = this.wasmModules.get(wasmPath);
          if (!wasmModule) {
            throw new Error(`wasm module '${wasmPath}' has not been initialized yet (at getAvailableWorkerInfo).`);
          }
          this.setInitialMsgHandling(worker);
          workerInfo = {
            id: id,
            status: this.S_RUNNING,
            jsPath: jsPath,
            memory: memory,
            worker: worker,
            module: wasmModule,
          };
          this.workerInfoPool.push(workerInfo);
          worker.postMessage({
            cmd: "initWasm",
            workerId: id,
            wasmProgram: wasmPath,
            wasmMemory: memory,
            wasmModule: wasmModule
          });
        }
        return workerInfo;
      },
      rebootWorker(workerId) {
        let oldWorkerInfo = this.workerInfoPool[workerId];
        let jsPath = oldWorkerInfo.jsPath;
        let wasmPath = jsPath.slice(0, -3) + ".wasm";
        let newMemory = this.newProcessMemory(INITIAL_MEMORY_SIZE);
        let newWorker = new Worker(new URL(jsPath, import.meta.url), {
          type: "module",
          name: `${jsPath}-worker-${workerId}`,
        });
        let wasmModule = oldWorkerInfo.module;
        this.setInitialMsgHandling(newWorker);
        this.workerInfoPool[workerId] = {
          id: oldWorkerInfo.id,
          status: this.S_STOP,
          jsPath: jsPath,
          memory: newMemory,
          worker: newWorker,
          module: wasmModule,
        };
        newWorker.postMessage({
          cmd: "initWasm",
          workerId: workerId,
          wasmProgram: wasmPath,
          wasmMemory: newMemory,
          wasmModule: wasmModule,
        })
      },
      setInitialMsgHandling(worker) {
        worker.onmessage = e => {
          let d = e["data"];

          tEcvPid = d.ecvPid;

          // run system call.
          if (d.cmd === "sysRun") {
            runSyscall(d);
          }
          // check whether PTY is ready or not
          else if (d.cmd === "PTY_ReadableCheck") {
            PTY_ReadableAtomicCheck(PTY_AtomicBuffer);
          }
          // init Wasm Finish notify
          else if (d.cmd === "initWasmDone") {
            console.log(`workerId ${d.workerId} is ready.`);
            if (!initProcessInitialized) {
              initWasmDoneNum++;
              if (initWasmDoneNum === userBinList.length * this.dupWorkerNum) {
                // start init process after all initial workers created.
                newProcess(initProcessJsPath, false);
                initProcessInitialized = true;
              }
            }
          }
          // exit handling
          else if (d.cmd === "exitSuccess") {
            exitHandling(d.workerId);
            this.rebootWorker(d.workerId);
          }
          // unknown cmd.
          else {
            throw e;
          }
        };
      },
      async createWasmModules(binList) {
        for (let ELF_Bin of binList) {
          try {
            let wasmPath = ELF_Bin + ".wasm";
            const url = new URL(wasmPath, import.meta.url).href;
            const resp = await fetch(url, { credentials: "same-origin" });
            const wasmBytes = await resp.arrayBuffer();
            const wasmModule = await WebAssembly.compile(wasmBytes);

            this.wasmModules.set(wasmPath, wasmModule);

          } catch (reason) {
            err(`wasm streaming compile failed: ${reason}`);
            err("falling back to ArrayBuffer instantiation");
          }
        }
      },
    };

    function newSession(pid) {
      return {
        sessionId: pid,
        controllingTTY: TTY.ttys[FS.makedev(5, 0)], // /dev/tty
      };
    }

    // system call handling.
    function runSyscall(d) {
      gWasmMemory = processes.get(d.ecvPid).wasmMemory;
      updateMemoryViews(gWasmMemory);

      let m32View = new Int32Array(gWasmMemory.buffer);

      let headPtr32 = d.spHead32;
      let sysNum = m32View[headPtr32];
      let argsNum = m32View[headPtr32 + 1];

      let sysRvalPtr = headPtr32 + 2 + argsNum;
      let waitPtr = sysRvalPtr + 1;

      let sysArgs = new Int32Array(argsNum);

      for (var i = 0; i < argsNum; i++) {
        sysArgs[i] = m32View[headPtr32 + 2 + i];
      }

      let tgtKernelFunction = SysFuncMap.get(sysNum);
      if (!tgtKernelFunction) {
        throw new Error(`unknown syscall: ${sysNum}`);
      }
      if (tgtKernelFunction.length != argsNum) {
        throw new Error(`argsNum (${argsNum}) must be equal to the args number (length: ${tgtKernelFunction.length}) of the syscall (sysNum: ${sysNum}).`);
      }

      // call the target kernel function.
      let sysRval = tgtKernelFunction(...sysArgs);
      // store the return value of syscall function executing.
      m32View[sysRvalPtr] = sysRval;

      // notify to process worker
      Atomics.store(m32View, waitPtr, 1);
      Atomics.notify(m32View, waitPtr, 1);
    }

    function exitHandling(workerId) {
      let tWorkerInfo = WORKER_MGR.workerInfoPool[workerId];
      tWorkerInfo.memory = WORKER_MGR.newProcessMemory(INITIAL_MEMORY_SIZE);
      // set the worker status `S_STOP`
      tWorkerInfo.status = WORKER_MGR.S_STOP;
    }

    // create new process
    // We assumes that init Wasm process (!isForked) already has `session` and `controlling terminal`
    // and the assumption is likely acceptable for many Linux processes.
    function newProcess(jsPath, isForked, parEcvPid, sDataSrcP, sDataLen, mBytesSrcP, mBytesLen) {

      // various ids.
      let ecvPid = getNewEcvPid();
      let ecvParPid = isForked ? parEcvPid : 0;
      let ecvPgid = isForked ? processes.get(parEcvPid).ecvPgid : ecvPid;
      // assumes that session has been set, so init Wasm call `newSession` instead of `undefined`.
      let session = isForked ? processes.get(parEcvPid).session : newSession(ecvPid);

      tEcvPid = ecvPid;

      // init FD table.
      FS.initFDTable(ecvPid, ecvParPid);

      if (!isForked) {
        // init standard stream.
        FS.initStandardStream();
        // register foreground process group for controlling terminal.
        session.controllingTTY.fgPgid = ecvPgid;
      }

      // shared array buffer for synchronous process between js-kernel and process-worker.
      let copyFinBell = new SharedArrayBuffer(4);
      // [0]. 0: initial, 1: execve success, 2: fail, 3: copy success 
      // [1]: used for returning `argc` to the new execved process worker.
      let execveBuf = new SharedArrayBuffer(8);
      // child monitoring ring buffer.
      // [RingBufferLock (4 byte); Empty (4 byte); head (4 byte); tail (4 byte); [ecvPid list] (4 * (childProcessMax + 1)) byte)]  // child processes is 20 at maximum
      // RingBufferLock. 0: Free, 1: Lock
      let childMonitor = (() => { let childMonitor = new SharedArrayBuffer(4 * 4 + 4 * (childProcessMax + 1)); let view = new Int32Array(childMonitor); view.set([0, 1, 0, 0], 0); return childMonitor })();
      let parMonitor = isForked ? processes.get(parEcvPid).childMonitor : undefined;

      let wasmProgram = isForked ? processes.get(parEcvPid).wasmProgram : Module["initProgram"];

      // get or init Worker (Wasm module initialization should start at this point)
      let workerInfo = WORKER_MGR.getAvailableWorkerInfo(jsPath);
      let processWorker = workerInfo.worker;
      let newWMemory = workerInfo.memory;

      // add fork state copy handling to the message handling.
      if (isForked) {
        let initialMsgHandling = processWorker.onmessage;
        processWorker.onmessage = e => {
          let d = e["data"];

          tEcvPid = d.ecvPid;

          if (d.cmd === "forkMemoryCopy") {
            let parWMemory = processes.get(parEcvPid).wasmMemory;
            // copy `memory_arena_bytes`
            let parWMemory8_1 = new Uint8Array(parWMemory.buffer);
            (growMemViews(newWMemory), HEAPU8).set(parWMemory8_1.subarray(mBytesSrcP, mBytesSrcP + mBytesLen), d.mBytesDstP);
            // write `child_pid` and `parent_pid` to the shared data buffer before copy.
            let parWMemory32 = new Uint32Array(parWMemory.buffer);
            parWMemory32[sDataSrcP + (sDataLen - 12) >> 2] = ecvPid;
            parWMemory32[sDataSrcP + (sDataLen - 8) >> 2] = parEcvPid;
            parWMemory32[sDataSrcP + (sDataLen - 4) >> 2] = ecvPgid;
            // copy `shared_data`
            let parWMemory8_2 = new Uint8Array(parWMemory.buffer);
            (growMemViews(newWMemory), HEAPU8).set(parWMemory8_2.subarray(sDataSrcP, sDataSrcP + sDataLen), d.sDataDstP);

            // update processes relatioinship.
            processes.get(parEcvPid).childs.add(tEcvPid);

            // notify to parent process worker.
            let parBellView = new Int32Array(processes.get(parEcvPid).copyFinBell);
            Atomics.store(parBellView, 0, 1);
            Atomics.notify(parBellView, 0, 1);

            // notify to this process worker.
            let chBellView = new Int32Array(copyFinBell);
            Atomics.store(chBellView, 0, 1);
            Atomics.notify(chBellView, 0, 1);
          } else {
            initialMsgHandling(e);
          }
        }
      }

      processes.set(ecvPid, {
        ecvPid: ecvPid,
        ecvParPid: ecvParPid,
        ecvPgid: ecvPgid,
        session: session,
        wasmProgram: wasmProgram,
        worker: processWorker,
        wasmMemory: newWMemory,
        copyFinBell: copyFinBell,
        execveBuf: execveBuf,
        parent: isForked ? parEcvPid : undefined,
        childs: new Set(),
        childMonitor: childMonitor,
        parMonitor: parMonitor,
      });

      // start this process.
      processWorker.postMessage({
        cmd: "startProcess",
        processType: isForked ? "forked" : "init",
        ecvPid: ecvPid,
        wasmMemory: newWMemory,
        copyFinBell: copyFinBell,
        childMonitor: childMonitor,
        parMonitor: parMonitor,
        execveBuf: execveBuf,
        PTY_AtomicBuffer: PTY_AtomicBuffer,
        FIFO_AtomicBuf: FIFO_AtomicBuf,
      });

      return ecvPid;
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

    async function initRuntime() {
      TTY.init(); // actually, this do nothing.
      FS.ignorePermissions = false
      await WORKER_MGR.createWasmModules(userBinList);
      console.log(WORKER_MGR.wasmModules);
      WORKER_MGR.init(userBinList);
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
    // const ECV_PSELECT6 = 72; // no need
    // const ECV_PPOLL = 73; // no need
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
    const ECV_LSTAT64 = 10000;
    // const ECV_ENVIRON_GET = 10001;
    // const ECV_ENVIRON_SIZES_GET = 10002;

    // select/poll
    const ECV_POLL_SCAN = 10003;
    const ECV_PSELECT6_SCAN = 10004;

    // pipe2
    const ECV_GET_DEV_TYPE = 10005;
    const ECV_FIFO_READ = 10006;
    const ECV_FIFO_WRITE = 10007;

    SysFuncMap.set(ECV_CLONE, ___syscall_clone);
    SysFuncMap.set(ECV_WAIT4, ___syscall_wait4);
    SysFuncMap.set(ECV_EXECVE, ___syscall_execve);
    SysFuncMap.set(ECV_CHDIR, ___syscall_chdir);
    SysFuncMap.set(ECV_DUP, ___syscall_dup);
    SysFuncMap.set(ECV_DUP3, ___syscall_dup3);
    SysFuncMap.set(ECV_FACCESSAT, ___syscall_faccessat);
    SysFuncMap.set(ECV_FCNTL, ___syscall_fcntl64);
    SysFuncMap.set(ECV_NEWFSTAT, ___syscall_fstat64);
    SysFuncMap.set(ECV_FTRUNCATE, ___syscall_ftruncate64);
    SysFuncMap.set(ECV_GETCWD, ___syscall_getcwd);
    SysFuncMap.set(ECV_GETDENTS, ___syscall_getdents64);
    SysFuncMap.set(ECV_IOCTL, ___syscall_ioctl);
    SysFuncMap.set(ECV_MKDIRAT, ___syscall_mkdirat);
    SysFuncMap.set(ECV_NEWFSTATAT, ___syscall_newfstatat);
    SysFuncMap.set(ECV_OPENAT, ___syscall_openat);
    SysFuncMap.set(ECV_SENDFILE, ___syscall_sendfile);
    // unused.
    // SysFuncMap.set(ECV_PPOLL, ___syscall_poll);
    SysFuncMap.set(ECV_READLINKAT, ___syscall_readlinkat);
    SysFuncMap.set(ECV_STATX, ___syscall_stat64);
    SysFuncMap.set(ECV_STATFS, ___syscall_statfs64);
    SysFuncMap.set(ECV_TRUNCATE, ___syscall_truncate64);
    SysFuncMap.set(ECV_UNLINKAT, ___syscall_unlinkat);
    SysFuncMap.set(ECV_UTIMENSAT, ___syscall_utimensat);
    SysFuncMap.set(ECV_CLOSE, _fd_close);
    SysFuncMap.set(ECV_PIPE2, ___syscall_pipe2);
    SysFuncMap.set(ECV_READ, _fd_read);
    SysFuncMap.set(ECV_LSEEK, _fd_seek);
    SysFuncMap.set(ECV_WRITE, _fd_write);
    SysFuncMap.set(ECV_EXIT, ___syscall_exit);
    SysFuncMap.set(ECV_GETRANDOM, _random_get);
    SysFuncMap.set(ECV_SETPGID, ___syscall_setpgid);
    SysFuncMap.set(ECV_GETPGID, ___syscall_getpgid);

    // emscripten runtimes
    SysFuncMap.set(ECV_LSTAT64, ___syscall_lstat64);
    // SysFuncMap.set(ECV_ENVIRON_GET, 1001);
    // SysFuncMap.set(ECV_ENVIRON_SIZES_GET, 1002);

    // select/poll
    SysFuncMap.set(ECV_POLL_SCAN, ___syscall_poll_scan);
    SysFuncMap.set(ECV_PSELECT6_SCAN, ___syscall_pselect6_scan);

    // read/write for pipe2
    SysFuncMap.set(ECV_GET_DEV_TYPE, ___ecv_get_dev_type);
    SysFuncMap.set(ECV_FIFO_READ, _fd_fifo_read);
    SysFuncMap.set(ECV_FIFO_WRITE, _fd_fifo_write);


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
    var noExitRuntime = true;

    class ExceptionInfo {
      constructor(excPtr) {
        this.excPtr = excPtr;
        this.ptr = excPtr - 24
      }
      set_type(type) {
        (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 4 >> 2] = type
      }
      get_type() {
        return (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 4 >> 2]
      }
      set_destructor(destructor) {
        (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 8 >> 2] = destructor
      }
      get_destructor() {
        return (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 8 >> 2]
      }
      set_caught(caught) {
        caught = caught ? 1 : 0;
        (growMemViews(gWasmMemory), HEAP8)[this.ptr + 12] = caught
      }
      get_caught() {
        return (growMemViews(gWasmMemory), HEAP8)[this.ptr + 12] != 0
      }
      set_rethrown(rethrown) {
        rethrown = rethrown ? 1 : 0;
        (growMemViews(gWasmMemory), HEAP8)[this.ptr + 13] = rethrown
      }
      get_rethrown() {
        return (growMemViews(gWasmMemory), HEAP8)[this.ptr + 13] != 0
      }
      init(type, destructor) {
        this.set_adjusted_ptr(0);
        this.set_type(type);
        this.set_destructor(destructor)
      }
      set_adjusted_ptr(adjustedPtr) {
        (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 16 >> 2] = adjustedPtr
      }
      get_adjusted_ptr() {
        return (growMemViews(gWasmMemory), HEAPU32)[this.ptr + 16 >> 2]
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
    var initRandomFill = () => view => crypto.getRandomValues(view);
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
    var PTY_signalNameToCode = {
      SIGINT: 2,
      SIGQUIT: 3,
      SIGTSTP: 20,
      SIGWINCH: 28
    };
    var PTY = Module["pty"];
    var PTY_AtomicBuffer = new SharedArrayBuffer(4);
    var PTY_pollTimeout = 0;
    var PTY_askToWaitAgain = timeout => {
      PTY_pollTimeout = timeout;
      throw new FS.ErrnoError(1006)
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
    var TTY = {
      ttys: [],
      init() { },
      shutdown() { },
      register(dev, ops) {
        TTY.ttys[dev] = {
          input: [],
          output: [],
          fgPgid: null,
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
          if (buffer === (growMemViews(gWasmMemory), HEAP8)) {
            buffer = (growMemViews(gWasmMemory), HEAPU8);
          } else if (!(buffer instanceof Uint8Array)) {
            throw new Error(`Unexpected buffer type: ${buffer.constructor.name}`)
          }
          let arr = Array.from(buffer.subarray(offset, offset + length));
          PTY.write(arr);
          return length
        },
        poll: (stream, events, timeout) => {
          let readyEvents = () => ((events & POLLIN) && PTY.readable) || ((events & POLLOUT) && PTY.writable);
          if (!readyEvents() && timeout) {
            PTY_askToWaitAgain(timeout);
          }
          return (((events & POLLIN) && PTY.readable) ? POLLIN : 0) | (((events & POLLOUT) && PTY.writable) ? POLLOUT : 0);
        }
      },
      default_tty_ops: {
        get_char() { },
        put_char() { },
        fsync() { },
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
        put_char(tty, val) {
          if (val === null || val === 10) {
            err(UTF8ArrayToString(tty.output));
            tty.output = []
          } else {
            if (val != 0) tty.output.push(val)
          }
        },
        fsync(tty) {
          if (tty.output?.length > 0) {
            err(UTF8ArrayToString(tty.output));
            tty.output = []
          }
        }
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
          },
          fifo: {
            node: {
              getattr: MEMFS.node_ops.getattr,
              setattr: MEMFS.node_ops.setattr
            },
            stream: {
              read: MEMFS.stream_ops.read,
              write: MEMFS.stream_ops.write
            }
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
        } else if (FS.isFIFO(node.mode)) {
          node.node_ops = MEMFS.ops_table.fifo.node;
          node.stream_ops = MEMFS.ops_table.fifo.stream;
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
          if (buffer.buffer === (growMemViews(gWasmMemory), HEAP8).buffer) {
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
          if (!(flags & 2) && contents && contents.buffer === (growMemViews(gWasmMemory), HEAP8).buffer) {
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
              }
              (growMemViews(gWasmMemory), HEAP8).set(contents, ptr)
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
    var FS = {
      root: null,
      mounts: [],
      devices: {},
      streamMap: new Map(),
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
          if (!FS.streamMap.get(tEcvPid).get(fd)) {
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
      getStream: fd => FS.streamMap.get(tEcvPid).get(fd),
      createStream(stream, fd = -1) {
        stream = Object.assign(new FS.FSStream, stream);
        if (fd == -1) {
          fd = FS.nextfd()
        }
        stream.fd = fd;
        FS.streamMap.get(tEcvPid).set(fd, stream);
        return stream
      },
      closeStream(fd) {
        FS.streamMap.get(tEcvPid).set(fd, null);
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
      open(path, flags, mode = 438) { // 438 = 0o0666
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
        var seekable = false;
        if (!FS.isFIFO(node.mode)) {
          seekable = true;
        }
        let fd_flags = flags & O_CLOEXEC ? FD_CLOEXEC : 0;
        flags &= ~(128 | 512 | 131072);
        var stream = FS.createStream({
          node,
          path: FS.getPath(node),
          flags,
          fd_flags,
          seekable: seekable,
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
      initFDTable(ecvPid, parEcvPid) {
        if (!FS.streamMap.has(ecvPid)) {
          FS.streamMap.set(ecvPid, new Map());
        }
        if (parEcvPid == 0) {
          return;
        }
        for (var [fd, stream] of FS.streamMap.get(parEcvPid)) {
          FS.streamMap.get(ecvPid).set(fd, stream);
        }
      },
      closeOnExecFD(ecvPid) {
        for (var [_fd, stream] of FS.streamMap.get(ecvPid)) {
          if (stream.fd_flags & FD_CLOEXEC) {
            FS.close(stream);
          }
        }
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
        FS.mkdir("/home/web_user");
        FS.mkdir("/usr");
        FS.mkdir("/usr/bin");
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
        FS.mkdir("/dev/shm/tmp");
        FS.mkdir("/dev/pipe2");
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
          FS.symlink("/dev/tty", "/dev/stderr")
        }
        var stdin = FS.open("/dev/stdin", 0); // fd = 0
        var stdout = FS.open("/dev/stdout", 1); // fd = 1
        var stderr = FS.open("/dev/stderr", 1); // fd = 2
      },
      createUserExecutableFiles(userBinList) {
        let userBinSet = [...new Set(userBinList)];
        for (let bin of userBinSet) {
          FS.open("/usr/bin/" + bin, O_CREAT, S_IWUSR);
        }
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
      initStandardStream(input, output, error) {
        FS.initialized = true;
        input ??= Module["stdin"];
        output ??= Module["stdout"];
        error ??= Module["stderr"];
        FS.createStandardStreams(input, output, error);
        // locate the all user Wasm program on `/usr/bin`.
        FS.createUserExecutableFiles(userBinList);
      },
      quit() {
        FS.initialized = false;
        for (var [fd, stream] of FS.streamMap.get(tEcvPid)) {
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
          writeChunks(stream, (growMemViews(gWasmMemory), HEAP8), ptr, length, position);
          return {
            ptr,
            allocated: true
          }
        };
        node.stream_ops = stream_ops;
        return node
      }
    };
    var UTF8ToString = (ptr, maxBytesToRead) => ptr ? UTF8ArrayToString((growMemViews(gWasmMemory), HEAPU8), ptr, maxBytesToRead) : "";
    var SYSCALLS = {
      DEFAULT_POLLMASK: POLLIN | POLLOUT | POLLOUT,
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
        (growMemViews(gWasmMemory), HEAP32)[buf >> 2] = stat.dev;
        (growMemViews(gWasmMemory), HEAP32)[buf + 4 >> 2] = stat.mode;
        (growMemViews(gWasmMemory), HEAPU32)[buf + 8 >> 2] = stat.nlink;
        (growMemViews(gWasmMemory), HEAP32)[buf + 12 >> 2] = stat.uid;
        (growMemViews(gWasmMemory), HEAP32)[buf + 16 >> 2] = stat.gid;
        (growMemViews(gWasmMemory), HEAP32)[buf + 20 >> 2] = stat.rdev;
        (growMemViews(gWasmMemory), HEAP64)[buf + 24 >> 3] = BigInt(stat.size);
        (growMemViews(gWasmMemory), HEAP32)[buf + 32 >> 2] = 4096;
        (growMemViews(gWasmMemory), HEAP32)[buf + 36 >> 2] = stat.blocks;
        var atime = stat.atime.getTime();
        var mtime = stat.mtime.getTime();
        var ctime = stat.ctime.getTime();
        (growMemViews(gWasmMemory), HEAP64)[buf + 40 >> 3] = BigInt(Math.floor(atime / 1e3));
        (growMemViews(gWasmMemory), HEAPU32)[buf + 48 >> 2] = atime % 1e3 * 1e3 * 1e3;
        (growMemViews(gWasmMemory), HEAP64)[buf + 56 >> 3] = BigInt(Math.floor(mtime / 1e3));
        (growMemViews(gWasmMemory), HEAPU32)[buf + 64 >> 2] = mtime % 1e3 * 1e3 * 1e3;
        (growMemViews(gWasmMemory), HEAP64)[buf + 72 >> 3] = BigInt(Math.floor(ctime / 1e3));
        (growMemViews(gWasmMemory), HEAPU32)[buf + 80 >> 2] = ctime % 1e3 * 1e3 * 1e3;
        (growMemViews(gWasmMemory), HEAP64)[buf + 88 >> 3] = BigInt(stat.ino);
        return 0
      },
      writeStatFs(buf, stats) {
        (growMemViews(gWasmMemory), HEAP32)[buf + 4 >> 2] = stats.bsize;
        (growMemViews(gWasmMemory), HEAP32)[buf + 40 >> 2] = stats.bsize;
        (growMemViews(gWasmMemory), HEAP32)[buf + 8 >> 2] = stats.blocks;
        (growMemViews(gWasmMemory), HEAP32)[buf + 12 >> 2] = stats.bfree;
        (growMemViews(gWasmMemory), HEAP32)[buf + 16 >> 2] = stats.bavail;
        (growMemViews(gWasmMemory), HEAP32)[buf + 20 >> 2] = stats.files;
        (growMemViews(gWasmMemory), HEAP32)[buf + 24 >> 2] = stats.ffree;
        (growMemViews(gWasmMemory), HEAP32)[buf + 28 >> 2] = stats.fsid;
        (growMemViews(gWasmMemory), HEAP32)[buf + 44 >> 2] = stats.flags;
        (growMemViews(gWasmMemory), HEAP32)[buf + 36 >> 2] = stats.namelen
      },
      doMsync(addr, stream, len, flags, offset) {
        if (!FS.isFile(stream.node.mode)) {
          throw new FS.ErrnoError(43)
        }
        if (flags & 2) {
          return 0
        }
        var buffer = (growMemViews(gWasmMemory), HEAPU8).slice(addr, addr + len);
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
      },
      // pipe2
      KERNEL_FIFOS: new Map(),
      pipe2Count: 0,
      getPipe2NewPath() {
        return "/dev/pipe2/node" + (++this.pipe2Count);
      }
    };

    function freeProcessWorker(ecvPid) {
      let thisPr = processes.get(ecvPid);
      processes.get(thisPr.ecvParPid).childs.delete(ecvPid);
      processes.delete(ecvPid);
      console.log(`Delete process ${ecvPid}. current processes: [${[...processes.keys()]}]`);
    }

    function ___syscall_clone(parEcvPid, sDataP, sDataPLen, mBytes, mBytesLen) {
      try {
        let child_pid = newProcess(initProcessJsPath, true, parEcvPid, sDataP, sDataPLen, mBytes, mBytesLen);
        return child_pid;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_wait4(ecvPid) {

      try {

        let thisEcvPr = processes.get(ecvPid);
        let monitorView = new Int32Array(thisEcvPr.childMonitor);

        // check all bell.
        let ringBell = Atomics.load(monitorView, 0);
        let emptyBell = Atomics.load(monitorView, 1);
        if (ringBell != 1 || emptyBell != 0) {
          throw new Error(`The bell when ___syscall_wait4 is called is strange. ringBell: ${ringBell}, emptyBell: ${emptyBell}`);
        }

        // get the target.
        let head = Atomics.load(monitorView, 2);
        let tail = Atomics.load(monitorView, 3);
        let waitEcvPid = Atomics.load(monitorView, prLingOffset + head);

        // free the target process.
        freeProcessWorker(waitEcvPid);

        // update head.
        let newHead = (head + 1) % childProcessMax;
        Atomics.store(monitorView, 2, newHead);
        if (newHead === tail) {
          // become empty.
          Atomics.store(monitorView, 1, 1);
        }

        return waitEcvPid;

      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_execve(ecvPid, fileNameP, argvP, envpP) {
      try {

        let thisPr = processes.get(ecvPid);
        let orgMemory = thisPr.wasmMemory;

        function readByteString(u8View, ptr8) {
          const bytes = [];
          while (u8View[ptr8] !== 0) {
            bytes.push(u8View[ptr8++]);
          }
          return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
        }

        function basename(path) {
          if (!path) return "";

          path = path.replace(/\/+$/, "");

          const idx = path.lastIndexOf("/");
          return idx >= 0 ? path.slice(idx + 1) : path;
        }

        let orgMemU8View = new Uint8Array(orgMemory.buffer);
        let orgMemU32View = new Uint32Array(orgMemory.buffer);

        // fileName
        let fileName = basename(readByteString(orgMemU8View, fileNameP));
        let execveWasm = fileName + '.wasm';
        let execveJs = fileName + '.js';

        console.log(`execveWasm: ${execveWasm}`);

        // get or init worker.
        let workerInfo = WORKER_MGR.getAvailableWorkerInfo(execveJs);
        let execveWorker = workerInfo.worker;
        let newMemory = workerInfo.memory;

        // update initial state
        thisPr.wasmMemory = newMemory;
        thisPr.copyFinBell = new SharedArrayBuffer(4);
        thisPr.wasmProgram = execveWasm;
        thisPr.worker = execveWorker;

        // close the FD of close-on-exec.
        FS.closeOnExecFD(ecvPid);

        // add execve args copy handling to the message handling.
        let initialMsgHandling = execveWorker.onmessage;
        execveWorker.onmessage = e => {
          let d = e["data"];

          tEcvPid = thisPr.ecvPid;

          if (d.cmd === "execveArgsCopy") {

            function countStringBytes(u8View, ptr8) {
              let len = 0;
              while (u8View[ptr8++] !== 0) {
                len++;
              }
              return len;
            }

            let execveBufview = new Int32Array(thisPr.execveBuf);

            // view
            let dst8View = new Int8Array(newMemory.buffer);
            let dst32View = new Int32Array(newMemory.buffer);

            // `argv`
            let argsTotal = 0, argId = 0;
            let srcArgvP32 = argvP >> 2;
            let srcArgvP8 = orgMemU32View[srcArgvP32];
            let dstArgvContentSid = d.argvContentP;
            while (srcArgvP8) {
              let argSpace = countStringBytes(orgMemU8View, srcArgvP8) + 1; // argSpace includes '\0'
              dst8View.set(orgMemU8View.subarray(srcArgvP8, srcArgvP8 + argSpace), dstArgvContentSid);
              dst32View[(d.argvP >> 2) + argId] = dstArgvContentSid;
              // increment
              srcArgvP32++;
              srcArgvP8 = orgMemU32View[srcArgvP32];
              dstArgvContentSid += argSpace;
              argId++;
              argsTotal += argSpace;
            }
            // default args bytes length threshold is 1,000.
            if (argsTotal >= 1000) {
              throw new Error(`argsTotal is too large at ___syscall_execve. execveWasm: ${execveWasm}, bytes len: ${argId}.`);
            }

            // `argc`
            Atomics.store(execveBufview, 1, argId);

            // `envp`
            let envsTotal, envId = 0;
            let srcEnvpP32 = envpP >> 2;
            let srcEnvpP8 = orgMemU32View[srcEnvpP32];
            let dstEnvpContentSid = d.envpContentP;
            while (srcEnvpP8) {
              let envSpace = countStringBytes(orgMemU8View, srcEnvpP8) + 1; // envSpace includes '\0'
              dst8View.set(orgMemU8View.subarray(srcEnvpP8, srcEnvpP8 + envSpace), dstEnvpContentSid);
              dst32View[(d.envpP >> 2) + envId] = dstEnvpContentSid;
              // increment
              srcEnvpP32++;
              srcEnvpP8 = orgMemU32View[srcEnvpP32];
              dstEnvpContentSid += envSpace;
              envId++;
              envsTotal += envSpace;
            }
            // default envs bytes length threshold is 5,000.
            if (envsTotal >= 5000) {
              throw new Error(`envsTotal is too large at ___syscall_execve. execveWasm: ${execveWasm}, bytes len: ${envId}.`);
            }

            // `ecvPid` (this and parent)
            dst32View[(d.ecvPidsP >> 2)] = thisPr.ecvPid;
            dst32View[(d.ecvPidsP >> 2) + 1] = thisPr.ecvParPid;
            dst32View[(d.ecvPidsP >> 2) + 2] = thisPr.ecvPgid;

            // notify copy success to the new execved worker.
            Atomics.store(execveBufview, 0, 3);
            // notify `two` workers (original worker and new worker).
            Atomics.notify(execveBufview, 0, 2);
          } else {
            initialMsgHandling(e);
          }
        };

        let execveBufView = new Int32Array(thisPr.execveBuf);

        // may be unnecessary.
        execveWorker.onerror = (err) => {
          console.error("Worker load failed:", err);
          // notify failure to the original worker.
          Atomics.store(execveBufView, 0, 2);
          Atomics.notify(execveBufView, 0, 1);
        }

        // init State.
        execveWorker.postMessage({
          cmd: "startProcess",
          processType: "execved",
          ecvPid: thisPr.ecvPid,
          copyFinBell: thisPr.copyFinBell,
          childMonitor: thisPr.childMonitor,
          parMonitor: thisPr.parMonitor,
          execveBuf: thisPr.execveBuf,
          PTY_AtomicBuffer: PTY_AtomicBuffer,
        });

        // notify success the original process worker.
        Atomics.store(execveBufView, 0, 1);
        Atomics.notify(execveBufView, 0, 1);

      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_exit(ecvPid, code) {

      try {

        let thisEcvPr = processes.get(ecvPid);

        if (thisEcvPr.childs.size > 0) {
          throw new Error(`The process having childs is not allowed to be exited in the current implementation.`);
        }

        if (thisEcvPr.parent) {
          // has parent
          let monitorView = new Int32Array(thisEcvPr.parMonitor);

          let ringBell = Atomics.load(monitorView, 0);
          if (ringBell != 1) {
            throw new Error(`___syscall_exit must be called when the monitor is locked. ringBell: ${ringBell}`);
          }

          // append the new process to the queue ring.
          let head = Atomics.load(monitorView, 2);
          let tail = Atomics.load(monitorView, 3);

          if (head === (tail + 1) % childProcessMax) {
            throw new Error(`too many processes at ___syscall_exit. head: ${head}, tail: ${tail}.`);
          }

          Atomics.store(monitorView, prLingOffset + tail, ecvPid);
          Atomics.store(monitorView, 3, (tail + 1) % childProcessMax);

          // become no empty. notify to waiting parent process.
          Atomics.store(monitorView, 1, 0);
          Atomics.notify(monitorView, 1, 1);

        } else {
          // init process.
          freeProcessWorker(ecvPid);
        }

      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_setpgid(tEcvPid, ecvPgid, myEcvPid) {
      try {
        if (tEcvPid == 0) {
          processes.get(myEcvPid).ecvPgid = ecvPgid;
        } else {
          processes.get(tEcvPid).ecvPgid = ecvPgid;
        }
        return 0;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -1
      }
    }

    function ___syscall_getpgid(tEcvPid, myEcvPid) {
      try {
        return tEcvPid == 0 ? processes.get(myEcvPid).ecvPgid : processes.get(tEcvPid).ecvPgid;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -1
      }
    }

    function ___syscall_chdir(path) {
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
      try {
        var old = SYSCALLS.getStreamFromFD(fd);
        return FS.dupStream(old).fd
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_dup3(fd, newfd, flags) {
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
      var ret = (growMemViews(gWasmMemory), HEAP32)[+SYSCALLS.varargs >> 2];
      SYSCALLS.varargs += 4;
      return ret
    };
    var syscallGetVarargP = syscallGetVarargI;

    function ___syscall_fcntl64(fd, cmd, varargs) {
      SYSCALLS.varargs = varargs;
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        switch (cmd) {
          case 0: {
            var arg = syscallGetVarargI();
            if (arg < 0) {
              return -28
            }
            while (FS.streamMap.get(tEcvPid).get(arg)) {
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
            (growMemViews(gWasmMemory), HEAP16)[arg + offset >> 1] = 2;
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
    var stringToUTF8 = (str, outPtr, maxBytesToWrite) => stringToUTF8Array(str, (growMemViews(gWasmMemory), HEAPU8), outPtr, maxBytesToWrite);

    function ___syscall_getcwd(buf, size) {
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
          }
          (growMemViews(gWasmMemory), HEAP64)[dirp + pos >> 3] = BigInt(id);
          (growMemViews(gWasmMemory), HEAP64)[dirp + pos + 8 >> 3] = BigInt((idx + 1) * struct_size);
          (growMemViews(gWasmMemory), HEAP16)[dirp + pos + 16 >> 1] = 280;
          (growMemViews(gWasmMemory), HEAP8)[dirp + pos + 18] = type;
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
      SYSCALLS.varargs = varargs;
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        switch (op) {
          case 21509: {
            if (!stream.tty) return -59;
            return 0
          }
          case 21505: { // TCGETS
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tcgets) {
              var termios = stream.tty.ops.ioctl_tcgets(stream);
              var argp = syscallGetVarargP();
              (growMemViews(gWasmMemory), HEAP32)[argp >> 2] = termios.c_iflag || 0;
              (growMemViews(gWasmMemory), HEAP32)[argp + 4 >> 2] = termios.c_oflag || 0;
              (growMemViews(gWasmMemory), HEAP32)[argp + 8 >> 2] = termios.c_cflag || 0;
              (growMemViews(gWasmMemory), HEAP32)[argp + 12 >> 2] = termios.c_lflag || 0;
              for (var i = 0; i < 32; i++) {
                (growMemViews(gWasmMemory), HEAP8)[argp + i + 17] = termios.c_cc[i] || 0
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
          case 21506: // TCSETS
          case 21507:
          case 21508: {
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tcsets) {
              var argp = syscallGetVarargP();
              var c_iflag = (growMemViews(gWasmMemory), HEAP32)[argp >> 2];
              var c_oflag = (growMemViews(gWasmMemory), HEAP32)[argp + 4 >> 2];
              var c_cflag = (growMemViews(gWasmMemory), HEAP32)[argp + 8 >> 2];
              var c_lflag = (growMemViews(gWasmMemory), HEAP32)[argp + 12 >> 2];
              var c_cc = [];
              for (var i = 0; i < 32; i++) {
                c_cc.push((growMemViews(gWasmMemory), HEAP8)[argp + i + 17])
              }
              return stream.tty.ops.ioctl_tcsets(stream.tty, op, {
                c_iflag,
                c_oflag,
                c_cflag,
                c_lflag,
                c_cc
              });
            }
            return 0
          }
          case 21519: { // TIOCGPGRP
            if (!stream.tty) return -59;
            var argp = syscallGetVarargP();
            if (stream.tty.fgPgid <= 0) {
              console.error(`foreground process group id (${stream.tty.fgPgid}) may be invalid? (tty: ${stream.tty})`);
            }
            (growMemViews(gWasmMemory), HEAP32)[argp >> 2] = stream.tty.fgPgid;
            return 0
          }
          case 21520: { // TIOCSPGRP
            if (!stream.tty) return -59;
            return -28
          }
          case 21531: {
            var argp = syscallGetVarargP();
            return FS.ioctl(stream, op, argp);
          }
          case 21523: { // TIOCGWINSZ
            if (!stream.tty) return -59;
            if (stream.tty.ops.ioctl_tiocgwinsz) {
              var winsize = stream.tty.ops.ioctl_tiocgwinsz(stream.tty);
              var argp = syscallGetVarargP();
              (growMemViews(gWasmMemory), HEAP16)[argp >> 1] = winsize[0];
              (growMemViews(gWasmMemory), HEAP16)[argp + 2 >> 1] = winsize[1];
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

    // missing coressponding system call number.
    function ___syscall_lstat64(path, buf) {
      try {
        path = SYSCALLS.getStr(path);
        return SYSCALLS.writeStat(buf, FS.lstat(path))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_mkdirat(dirfd, path, mode) {
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

    function ___syscall_poll_scan(fds, nfds, tmSec, tmNsec) {
      try {

        growMemViews(gWasmMemory);

        let timeout = 0;
        if (tmSec == -1) {
          timeout = -1;
        } else {
          timeout = tmSec + tmNsec * 1e-9;
        }

        let nonzero = 0;
        for (var i = 0; i < nfds; i++) {
          var pollfd = fds + 8 * i;
          var fd = HEAP32[pollfd >> 2];
          var events = HEAP16[pollfd + 4 >> 1];
          var mask = 32;
          var stream = FS.getStream(fd);
          if (stream) {
            if (stream.stream_ops.poll) {
              mask = stream.stream_ops.poll(stream, events, timeout)
            }
          }
          mask &= events | POLLERR | POLLHUP;
          if (mask) nonzero++;
          HEAP16[pollfd + 6 >> 1] = mask
        }
        return nonzero
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        console.log(`errno: ${e.errno}`);
        return -e.errno
      }
    }

    function ___syscall_pselect6_scan(nfds, readfdsP, writefdsP, exceptfdsP, tmSec, tmNsec, sigmaskP) {
      try {

        growMemViews(gWasmMemory);

        let timeout;
        if (tmSec == -1) {
          timeout = -1;
        } else {
          timeout = tmSec + tmNsec * 1e-9;
        }

        function checkFDs(fdsP, events) {

          let tFD = 0;

          for (let i = 0; i < __KERNEL_FD_SETMAXID * 2; i++) { // scan 32 bits at a time.
            for (let j = 0; j < 32; j++) {
              if ((HEAP32[(fdsP >> 2) + i] & (1 << j)) !== 0) {
                let stream = FS.getStream(tFD);
                let mask;
                if (stream) {
                  if (stream.stream_ops.poll) {
                    mask = stream.stream_ops.poll(stream, events, timeout);
                  }
                } else {
                  throw "FS not having stream may be invaild?";
                }
                let fdSetId = tFD / 32;
                let bitId = tFD % 32;
                if (mask & events) {
                  // the bit is set
                  HEAP32[(fdsP >> 2) + fdSetId] |= (1 << bitId);
                  nonzero++;
                } else {
                  // the bit is not set
                  HEAP32[(fdsP >> 2) + fdSetId] &= ~(1 << bitId);
                }
              }
              tFD++;
              if (tFD == nfds) {
                return nonzero;
              }
            }
          }

          return nonzero;
        }

        let nonzero = 0;
        nonzero += checkFDs(readfdsP, POLLIN);
        nonzero += checkFDs(writefdsP, POLLOUT);
        // nonzero += checkFDs(exceptfdsP, null); // rarely not used

        return nonzero;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    var PTY_ReadableAtomicCheckImpl = callback => {
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
    var PTY_ReadableAtomicCheck = function (atomicBuffer) {
      PTY_ReadableAtomicCheckImpl(type => {
        let PTY_AtomicView = new Int32Array(atomicBuffer);
        Atomics.store(PTY_AtomicView, 0, type);
        Atomics.notify(PTY_AtomicView, 0);
      })
    };

    function ___ecv_get_dev_type(fd) {
      try {
        let stream = FS.getStream(fd);
        return stream.node.mode & S_IFMT;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_readlinkat(dirfd, path, buf, bufsize) {
      try {
        path = SYSCALLS.getStr(path);
        path = SYSCALLS.calculateAt(dirfd, path);
        if (bufsize <= 0) return -28;
        var ret = FS.readlink(path);
        var len = Math.min(bufsize, lengthBytesUTF8(ret));
        var endChar = (growMemViews(gWasmMemory), HEAP8)[buf + len];
        stringToUTF8(ret, buf, bufsize + 1);
        (growMemViews(gWasmMemory), HEAP8)[buf + len] = endChar;
        return len
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_stat64(path, buf) {
      try {
        path = SYSCALLS.getStr(path);
        return SYSCALLS.writeStat(buf, FS.stat(path))
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_statfs64(path, size, buf) {
      try {
        SYSCALLS.writeStatFs(buf, FS.statfs(SYSCALLS.getStr(path)));
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function ___syscall_truncate64(path, length) {
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
    var readI53FromI64 = ptr => (growMemViews(gWasmMemory), HEAPU32)[ptr >> 2] + (growMemViews(gWasmMemory), HEAP32)[ptr + 4 >> 2] * 4294967296;

    function ___syscall_utimensat(dirfd, path, times, flags) {
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
          var nanoseconds = (growMemViews(gWasmMemory), HEAP32)[times + 8 >> 2];
          if (nanoseconds == 1073741823) {
            atime = now
          } else if (nanoseconds == 1073741822) {
            atime = null
          } else {
            atime = seconds * 1e3 + nanoseconds / (1e3 * 1e3)
          }
          times += 16;
          seconds = readI53FromI64(times);
          nanoseconds = (growMemViews(gWasmMemory), HEAP32)[times + 8 >> 2];
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
    var runtimeKeepaliveCounter = 0;
    var ENV = {};
    var getExecutableName = () => initProcessJsPath;
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

    var keepRuntimeAlive = () => noExitRuntime || runtimeKeepaliveCounter > 0;

    function _proc_exit(code) {
      EXITSTATUS = code;
      if (!keepRuntimeAlive()) {
        Module["onExit"]?.(code);
        ABORT = true
      }
      quit_(code, new ExitStatus(code))
    };
    var exitJS = (status, implicit) => {
      EXITSTATUS = status;
      _proc_exit(status)
    };
    var _exit = exitJS;

    function _fd_close(fd) {
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
        var ptr = (growMemViews(gWasmMemory), HEAPU32)[iov >> 2];
        var len = (growMemViews(gWasmMemory), HEAPU32)[iov + 4 >> 2];
        iov += 8;
        var curr = FS.read(stream, (growMemViews(gWasmMemory), HEAP8), ptr, len, offset);
        if (curr < 0) return -1;
        ret += curr;
        if (curr < len) break;
        if (typeof offset != "undefined") {
          offset += curr
        }
      }
      return ret
    };

    function ___syscall_pipe2(pipefd, flags) {
      try {
        let path = SYSCALLS.getPipe2NewPath();
        let streamRead = FS.open(path, (flags & ~0b11) | O_CREAT | O_RDONLY, S_IFIFO | 0o600);
        let streamWrite = FS.open(path, (flags & ~0b11) | O_CREAT | O_WRONLY, S_IFIFO | 0o600);
        (growMemViews(gWasmMemory), HEAPU32)[pipefd >> 2] = streamRead.fd;
        (growMemViews(gWasmMemory), HEAPU32)[pipefd + 4 >> 2] = streamWrite.fd;
        SYSCALLS.KERNEL_FIFOS.set(streamRead.node.id, {
          head: 0,
          tail: 0,
        });
        return 0;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno;
      }
    }

    function ___syscall_sendfile(out_fd, in_fd, offsetP, count) {
      try {
        let outStream = SYSCALLS.getStreamFromFD(out_fd);
        let inStream = SYSCALLS.getStreamFromFD(in_fd);
        let tmpBuf = new Uint8Array(count);
        // use `read` and `write` instead of directly transportation.
        let readLen;
        if (offsetP) {
          let position = (growMemViews(gWasmMemory), HEAPU32)[offsetP >> 2];
          readLen = FS.read(inStream, tmpBuf, 0, count, position);
          (growMemViews(gWasmMemory), HEAPU32)[offsetP >> 2] = position + readLen;
        } else {
          readLen = FS.read(inStream, tmpBuf, 0, count);
          (growMemViews(gWasmMemory), HEAPU32)[offsetP >> 2] = inStream.position;
        }
        return FS.write(outStream, tmpBuf, 0, readLen, undefined, true);
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return -e.errno
      }
    }

    function _fd_read(fd, iov, iovcnt, pnum) {
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        var num = doReadv(stream, iov, iovcnt);
        (growMemViews(gWasmMemory), HEAPU32)[pnum >> 2] = num;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _fd_fifo_read(fd, bufP, len, pnum, bszP) {
      try {
        let stream = SYSCALLS.getStreamFromFD(fd);
        let tFIFO = SYSCALLS.KERNEL_FIFOS.get(stream.node.id);
        if (!tFIFO) {
          throw FS.ErrnoError(106);
        }
        let num = FS.read(stream, (growMemViews(gWasmMemory), HEAP8), bufP, len, tFIFO.head);
        // update ring buffer size.
        if (tFIFO.head + num <= tFIFO.tail) {
          tFIFO.head += num;
        } else {
          throw new Error(`tFIFO head succeeds the tail at calling _fd_fifo_read. node_name: ${stream.node.name}, head: ${tFIFO.head}, tail: ${tFIFO.tail}`)
        }
        // save bsz
        (growMemViews(gWasmMemory), HEAP32)[bszP >> 2] = (tFIFO.tail - tFIFO.head);
        (growMemViews(gWasmMemory), HEAPU32)[pnum >> 2] = num;
        return 0;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _fd_seek(fd, offset, whence, newOffset) {
      offset = bigintToI53Checked(offset);
      try {
        if (isNaN(offset)) return 61;
        var stream = SYSCALLS.getStreamFromFD(fd);
        FS.llseek(stream, offset, whence);
        (growMemViews(gWasmMemory), HEAP64)[newOffset >> 3] = BigInt(stream.position);
        if (stream.getdents && offset === 0 && whence === 0) stream.getdents = null;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _fd_sync(fd) {
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
        var ptr = (growMemViews(gWasmMemory), HEAPU32)[iov >> 2];
        var len = (growMemViews(gWasmMemory), HEAPU32)[iov + 4 >> 2];
        iov += 8;
        var curr = FS.write(stream, (growMemViews(gWasmMemory), HEAP8), ptr, len, offset);
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
      try {
        var stream = SYSCALLS.getStreamFromFD(fd);
        var num = doWritev(stream, iov, iovcnt);
        (growMemViews(gWasmMemory), HEAPU32)[pnum >> 2] = num;
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _fd_fifo_write(fd, bufP, len, bszP, pnum) {
      try {
        let stream = SYSCALLS.getStreamFromFD(fd);
        let tFIFO = SYSCALLS.KERNEL_FIFOS.get(stream.node.id);
        if (!tFIFO) {
          throw FS.ErrnoError(106);
        }
        let num = FS.write(stream, (growMemViews(gWasmMemory), HEAP8), bufP, len); // offset is skipeed same as to `_fd_write`.
        // update ring buffer position.
        if (tFIFO.tail + len <= PIPE_MAX_SZ) {
          tFIFO.tail += len;
        } else {
          throw new Error(`tFIFO tail succeeds 'PIPE_MAX_SZ' at calling _fd_fifo_write. node_name: ${stream.node.name}, head: ${tFIFO.head}, tail: ${tFIFO.tail}`);
        }
        // save bsz
        (growMemViews(gWasmMemory), HEAP32)[bszP >> 2] = (tFIFO.tail - tFIFO.head);
        (growMemViews(gWasmMemory), HEAPU32)[pnum >> 2] = num;
        return 0;
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    function _random_get(buffer, size) {
      try {
        randomFill((growMemViews(gWasmMemory), HEAPU8).subarray(buffer, buffer + size));
        return 0
      } catch (e) {
        if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
        return e.errno
      }
    }

    FS.createPreloadedFile = FS_createPreloadedFile;
    FS.staticInit();
    MEMFS.doesNotExistError = new FS.ErrnoError(44);
    MEMFS.doesNotExistError.stack = "<generic error, no stack>";
    {
      if (Module["noExitRuntime"]) noExitRuntime = Module["noExitRuntime"];
      if (Module["preloadPlugins"]) preloadPlugins = Module["preloadPlugins"];
      if (Module["print"]) out = Module["print"];
      if (Module["printErr"]) err = Module["printErr"];
      if (Module["arguments"]) arguments_ = Module["arguments"];
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

      function doRun() {
        initRuntime();
        preMain();
        readyPromiseResolve(Module);
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

    moduleRtn = readyPromise;
    return moduleRtn;
  });
})();
export default Module;