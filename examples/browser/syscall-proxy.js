/// syscall-proxy.js 
var wasmMemory;
var workerId;
var copyNoteBell;

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
    workerId = d.workerId;
    copyNoteBell = d.copyBell;
    assignWasmImports();
  } else if (d.cmd === "startWorker") {
    if (d.entry === "main") {
      startWorker();
    } else if (d.entry === "forkMain") {
      // waits copySData finishing on the js-kernel side. 
      let bellView = new Int32Array(copyNoteBell);
      Atomics.wait(bellView, 0, 0);
      // entry fork process.
      _fork_main();
    } else {
      throw e;
    }
  } else if (d.cmd === "takeSDataP") {
    console.log("enter takeSDataP!");
    let sDataP32 = _get_shared_data_p() >> 2;
    let _mBytesP8 = (growMemViews(wasmMemory), HEAP32)[sDataP32];
    let _sDataP8 = (growMemViews(wasmMemory), HEAP32)[sDataP32 + 1];
    postMessage({
      cmd: "giveSDataP",
      mBytesP8: _mBytesP8,
      sDataP8: _sDataP8,
    });
  } else {
    throw e;
  }
}

// This function assumes that emscripten JS syscall is executed synchronously.
function ecvProxySyscallJs(sysNum, ...callArgs) {

  // setting of pMemory32
  // [sysNum (4byte); argsNum (4byte); args (4 * sysNum byte); sysRval (4byte); waitSpace (4byte)]

  console.log(`ecvProxySyscallJs start [sysNum: ${sysNum}] (hello.js).`);

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

  (growMemViews(wasmMemory), HEAP32)[headPtr32] = sysNum;

  let argsNum = 0;

  for (let i = 0; i < callArgs.length; i++) {
    (growMemViews(wasmMemory), HEAP32)[headPtr32 + 2 + i] = callArgs[i];
    argsNum += 1;
  }

  (growMemViews(wasmMemory), HEAP32)[headPtr32 + 1] = argsNum;
  Atomics.store((growMemViews(wasmMemory), HEAP32), waitPtr, 0);

  // notify to js-kernel.
  postMessage({
    cmd: "sysRun",
    workerId: workerId,
    spHead32: headPtr32
  });

  console.log("post to js-kernel (hello.js).");

  // waiting for syscall finishing (of js-kernel).
  // (FIXME?) It seems that we can't guarantee the consistency?
  Atomics.wait((growMemViews(wasmMemory), HEAP32), waitPtr, 0);

  // wake up (from js-kernel).
  let notifyVal = Atomics.load((growMemViews(wasmMemory), HEAP32), waitPtr);
  if (notifyVal != 1) {
    throw `nofityVal (${notifyVal}) at ecvProxySyscallJs(sysNum, ...callArgs) is strange.`;
  }

  let sysRval = (growMemViews(wasmMemory), HEAP32)[sysRvalPtr];
  console.log(`sysRval: ${sysRval}`);

  stackRestore(sp);
  return sysRval;
}