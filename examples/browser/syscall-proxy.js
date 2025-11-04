/// syscall-proxy.js 
var wasmMemory;
var pMemory32View;
var ecvPid;
var copyFinBell;
var childMonitor;
var parMonitor;
var initPromise;

function growMemViews(pWasmMemory) {
  if (pWasmMemory.buffer != HEAP8.buffer) {
    updateMemoryViews(pWasmMemory);
  }
}

// register the process of postMessage from js-kernel.
self.onmessage = e => {
  let d = e["data"];
  if (d.cmd === "initState") {

    wasmMemory = d.pWasmMemory;
    pMemory32View = new Int32Array(wasmMemory.buffer);
    ecvPid = d.ecvPid;
    copyFinBell = d.copyFinBell;
    childMonitor = d.childMonitor;
    parMonitor = d.parMonitor;

    assignWasmImports();
    updateMemoryViews(wasmMemory);
    initPromise = initWasmModule();
    initPromise.then(() => {
      postMessage({ cmd: "initOk" });
    });

  } else if (d.cmd === "startWorker") {
    initPromise.then(() => run());
  } else if (d.cmd === "takeSDataP") {
    (growMemViews(wasmMemory), HEAP32)[_me_forked >> 2] = 1;
    postMessage({
      cmd: "giveSDataP",
    })
  } else {
    throw e;
  }
}

function ecv_proxy_process_memory_copy_req(memory_arena_bytes, shared_data) {
  let bellView = new Int32Array(copyFinBell);
  Atomics.store(bellView, 0, 0);
  postMessage({
    cmd: "mCopy",
    mBytesDstP: memory_arena_bytes,
    sDataDstP: shared_data,
  });
  Atomics.wait(bellView, 0, 0);
  let resBell = Atomics.load(bellView, 0);
  if (resBell != 1) {
    throw new Error(`mCopyBell(${resBell}) is strange.`)
  }
}

// This function assumes that emscripten JS syscall is executed synchronously.
function ecvProxySyscallJs(sysNum, ...callArgs) {

  // setting of pMemory32
  // [sysNum (4byte); argsNum (4byte); args (4 * sysNum byte); sysRval (4byte); waitSpace (4byte)]

  // console.log(`ecvProxySyscallJs start [sysNum: ${sysNum}] (ecvPid: ${ecvPid}).`);

  let sp = stackSave();
  let newAllocSz = 4 // sysNum
    + 4 // argsNum
    + (callArgs.length * 4) // args
    + 4 // sysRval
    + 4; // waitSpace
  let headPtr = stackAlloc(newAllocSz);
  let headPtr32 = headPtr >> 2;
  let sysRvalPtr = headPtr32 + (newAllocSz >> 2) - 2;
  let waitPtr = sysRvalPtr + 1;

  (growMemViews(wasmMemory), pMemory32View)[headPtr32] = sysNum;

  let argsNum = 0;

  for (let i = 0; i < callArgs.length; i++) {
    (growMemViews(wasmMemory), pMemory32View)[headPtr32 + 2 + i] = callArgs[i];
    argsNum += 1;
  }

  (growMemViews(wasmMemory), pMemory32View)[headPtr32 + 1] = argsNum;
  Atomics.store((growMemViews(wasmMemory), pMemory32View), waitPtr, 0);

  // notify to js-kernel.
  postMessage({
    cmd: "sysRun",
    ecvPid: ecvPid,
    spHead32: headPtr32
  });

  // waiting for syscall finishing (of js-kernel).
  // (FIXME?) It seems that we can't guarantee the consistency?
  Atomics.wait((growMemViews(wasmMemory), pMemory32View), waitPtr, 0);

  // wake up (from js-kernel).
  let notifyVal = Atomics.load((growMemViews(wasmMemory), pMemory32View), waitPtr);
  if (notifyVal != 1) {
    throw `nofityVal (${notifyVal}) at ecvProxySyscallJs(sysNum, ...callArgs) is strange.`;
  }

  let sysRval = (growMemViews(wasmMemory), pMemory32View)[sysRvalPtr];
  // console.log(`sysRval: ${sysRval}`);

  stackRestore(sp);
  return sysRval;
}

// clone syscall wrapper.
function _wrap_clone_syscall_js(sysNum, ptr, len) {

  let ptr32 = ptr >> 2;
  const args = (growMemViews(wasmMemory), HEAP32).subarray(ptr32, ptr32 + len);

  let bellView = new Int32Array(copyFinBell);
  Atomics.store(bellView, 0, 0);

  // clone syscall entry.
  let sysRes = ecvProxySyscallJs(sysNum, ...args);

  // waiting until process state copy has been finished.
  Atomics.wait(bellView, 0, 0);

  let copyFinBellRes = Atomics.load(bellView, 0);
  if (copyFinBellRes != 1) {
    throw new Error(`copyFinBellRes (${copyFinBellRes}) is strange.`);
  }

  return sysRes;
}

// wait syscall wrapper.
function _wrap_wait_syscall_js(sysNum, ecvPid) {

  let childMonitorView = new Int32Array(childMonitor);

  // if no child exited process is on the ring buffer, the parent should wait.
  Atomics.wait(childMonitorView, 1, 1);

  // waked up. Atomics.load(childMonitorView, 1) is `0`.

  // should wait during the other process is operating the ring buffer. (FIXME?)
  Atomics.wait(childMonitorView, 0, 1)

  // waked up. Atomics.load(childMonitorView, 0) is `0`.

  // Lock ringBufferLock.
  Atomics.store(childMonitorView, 0, 1);

  let sysRes = ecvProxySyscallJs(sysNum, ecvPid);

  // Free ringBufferLock.
  Atomics.store(childMonitorView, 0, 0);
  Atomics.notify(childMonitorView, 0, 1);

  return sysRes;
}

// exit syscall wrapper.
function _wrap_exit_syscall_js(sysNum, ecvPid, code) {

  if (parMonitor) {
    // has parent
    let parMonitorView = new Int32Array(parMonitor);

    // should wait during the other process is operating the ring buffer. (FIXME?)
    Atomics.wait(parMonitorView, 0, 1);

    // waked up. Atomics.load(parMonitorView, 0) is `0`

    // Lock ringBufferLock.
    Atomics.store(parMonitorView, 0, 1);

    ecvProxySyscallJs(sysNum, ecvPid, code);

    // Free ringBufferLock.
    Atomics.store(parMonitorView, 0, 0);
    Atomics.notify(parMonitorView, 0, 1);
  } else {
    // init process.
    ecvProxySyscallJs(sysNum, ecvPid, code);
  }

  throw new Error(`exit process (${ecvPid})`);
}