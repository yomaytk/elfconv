/// syscall-proxy.js 
var wasmMemory = undefined;
var pMemory32View;

// register the process of postMessage from js-kernel-proxy.
self.onmessage = e => {
  let d = e["data"];
  if (d.cmd === "initMemory") {
    wasmMemory = d.pWasmMemory;
    pMemory32View = new Int32Array(wasmMemory.buffer);
    assignWasmImports();
  } else if (d.cmd === "startWorker") {
    startWorker();
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
  let newAllocSz = 4 + 4 + (callArgs.length * 4) + 4 + 4;
  let headPtr = stackAlloc(newAllocSz);
  let headPtr32 = headPtr >> 2;
  let sysRvalPtr = headPtr32 + (newAllocSz >> 2) - 2;
  let waitPtr = sysRvalPtr + 1;

  pMemory32View[headPtr32] = sysNum;

  let argsNum = 0;

  for (let i = 0; i < callArgs.length; i++) {
    // TODO update memory to the target exec worker.
    pMemory32View[headPtr32 + 2 + i] = callArgs[i];
    argsNum += 1;
  }

  pMemory32View[headPtr32 + 1] = argsNum;
  Atomics.store(pMemory32View, waitPtr, 0);

  // notify to js-kernel.
  postMessage({
    cmd: "sysRun",
    workerId: 0,
    spHead32: headPtr32
  });

  console.log("post to js-kernel (hello.js).");

  // waiting for syscall finishing (of js-kernel-proxy).
  // (FIXME?) It seems that we can't guarantee the consistency?
  Atomics.wait(pMemory32View, waitPtr, 0);

  // wake up (from js-kernel).
  let notifyVal = Atomics.load(pMemory32View, waitPtr);
  if (notifyVal != 1) {
    throw `nofityVal (${notifyVal}) at ecvProxySyscallJs(sysNum, ...callArgs) is strange.`;
  }

  let sysRval = pMemory32View[sysRvalPtr];
  console.log(`sysRval: ${sysRval}`);

  stackRestore(sp);
  return sysRval;
}