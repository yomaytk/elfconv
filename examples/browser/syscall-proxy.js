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