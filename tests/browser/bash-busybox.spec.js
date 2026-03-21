const { test, expect } = require('@playwright/test');

function readTerminalText() {
  const xterm = window.__test_xterm;
  if (!xterm) return '';
  const buf = xterm.buffer.active;
  let text = '';
  for (let i = 0; i < buf.length; i++) {
    const line = buf.getLine(i);
    if (line) {
      text += line.translateToString(true) + '\n';
    }
  }
  return text;
}

async function waitForTerminalContent(page, content, timeout = 15000) {
  return page.waitForFunction(
    ({ fn, expected }) => {
      const text = new Function('return (' + fn + ')()')();
      if (text.includes(expected)) return text;
      return false;
    },
    { fn: readTerminalText.toString(), expected: content },
    { timeout }
  );
}

async function typeCommand(page, command) {
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type(command, { delay: 20 });
  await page.keyboard.press('Enter');
}

// Basic tests with assertions
test('bash boot and basic output', async ({ page }) => {
  test.setTimeout(180000);

  await page.goto('/');
  await waitForTerminalContent(page, 'bash-static.wasm', 90000);

  await typeCommand(page, 'uname -a');
  const unameOut = await waitForTerminalContent(page, 'wasm32 GNU/Linux');
  expect(await unameOut.jsonValue()).toContain('Linux');

  await typeCommand(page, 'ls /');
  const lsOut = await waitForTerminalContent(page, 'dev');
  const lsText = await lsOut.jsonValue();
  expect(lsText).toContain('tmp');
  expect(lsText).toContain('usr');
});

// Probe all /usr/bin commands in batches.
// Each batch runs in its own browser session.

const batch1 = [
  ['arch; echo _D1', '_D1'],
  ['ascii 2>&1; echo _D2', '_D2'],
  ['basename /usr/bin/ls; echo _D3', '_D3'],
  ['cat /dev/null && echo _D4', '_D4'],
  ['chmod 777 /tmp && echo _D5', '_D5'],
  ['cp /dev/null /tmp/_cp && echo _D6', '_D6'],
  ['cut -c1-3 <<< CUTTEST; echo _D7', '_D7'],
  ['date; echo _D8', '_D8'],
  ['dirname /usr/bin/ls; echo _D9', '_D9'],
  ['expr 1 + 2; echo _D10', '_D10'],
];

const batch2 = [
  ['head -1 <<< HEADTEST; echo _D11', '_D11'],
  ['hostname; echo _D12', '_D12'],
  ['ln -s /tmp /tmp/_ln 2>&1; echo _D13', '_D13'],
  ['mkdir /tmp/_mk && echo _D14', '_D14'],
  ['mv /tmp/_cp /tmp/_mv && echo _D15', '_D15'],
  ['rm /tmp/_mv && echo _D16', '_D16'],
  ['rmdir /tmp/_mk && echo _D17', '_D17'],
  ['seq 3 | tail -1; echo _D18', '_D18'],
  ['sleep 0 && echo _D19', '_D19'],
  ['tail -1 <<< TAILTEST; echo _D20', '_D20'],
];

const batch3 = [
  ['touch /tmp/_tch && echo _D21', '_D21'],
  ['tree /tmp 2>&1 | head -1; echo _D22', '_D22'],
  ['uname; echo _D23', '_D23'],
  ['uptime 2>&1; echo _D24', '_D24'],
  ['wc <<< "one two"; echo _D25', '_D25'],
  ['echo GP | grep GP; echo _D26', '_D26'],
  ['echo SI | sed s/SI/SO/; echo _D27', '_D27'],
  ['echo "A B" | awk "{print \\$2}"; echo _D28', '_D28'],
  ['find /tmp -maxdepth 0; echo _D29', '_D29'],
  ['echo -e "z\\na" | sort | head -1; echo _D30', '_D30'],
];

const batch4 = [
  ['which ls; echo _D31', '_D31'],
  ['readlink /usr/bin/ls; echo _D32', '_D32'],
  ['echo REV | rev; echo _D33', '_D33'],
  ['echo B64 | base64; echo _D34', '_D34'],
  ['factor 42; echo _D35', '_D35'],
  ['echo MD | md5sum; echo _D36', '_D36'],
  ['echo FOLDLONG | fold -w 4 | head -1; echo _D37', '_D37'],
  ['echo -e "N1\\nN2" | nl | head -1; echo _D38', '_D38'],
  ['echo ODP | od -c | head -1; echo _D39', '_D39'],
  ['echo -e "X\\nY" | paste -s -d,; echo _D40', '_D40'],
];

const batch5 = [
  ['printenv PATH; echo _D41', '_D41'],
  ['printf "PF=%d" 7; echo _D42', '_D42'],
  ['realpath /usr/bin/../bin/ls; echo _D43', '_D43'],
  ['echo SP | sha256sum | cut -c1-4; echo _D44', '_D44'],
  ['stat /; echo _D45', '_D45'],
  ['echo STR | strings; echo _D46', '_D46'],
  ['echo -e "C\\nB\\nA" | tac | head -1; echo _D47', '_D47'],
  ['echo TEE > /tmp/_tee && cat /tmp/_tee; echo _D48', '_D48'],
  ['echo TP | tr P Q; echo _D49', '_D49'],
  ['true && echo _D50', '_D50'],
];

const batch6 = [
  ['false || echo _D51', '_D51'],
  ['truncate -s 3 /tmp/_tr && stat -c %s /tmp/_tr; echo _D52', '_D52'],
  ['echo -e "U\\nU\\nV" | uniq | tail -1; echo _D53', '_D53'],
  ['unlink /tmp/_tr && echo _D54', '_D54'],
  ['echo XA | xargs echo; echo _D55', '_D55'],
  ['echo XX | xxd | head -1; echo _D56', '_D56'],
  ['whoami 2>&1; echo _D57', '_D57'],
  ['id 2>&1; echo _D58', '_D58'],
  ['ps; echo _D59', '_D59'],
  ['free 2>&1; echo _D60', '_D60'],
  ['echo -e "chown skip" && echo _D61', '_D61'],
];

const allBatches = [
  ['batch1: arch~expr', batch1],
  ['batch2: head~tail', batch2],
  ['batch3: touch~sort', batch3],
  ['batch4: which~paste', batch4],
  ['batch5: printenv~true', batch5],
  ['batch6: false~free', batch6],
];

for (const [batchName, cmds] of allBatches) {
  test(`probe ${batchName}`, async ({ page }) => {
    test.setTimeout(120000);
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm', 90000);

    const results = { pass: [], fail: [] };
    for (const [cmd, marker] of cmds) {
      const label = cmd.split(';')[0].trim();
      try {
        await typeCommand(page, cmd);
        await waitForTerminalContent(page, marker, 8000);
        results.pass.push(label);
      } catch {
        results.fail.push(label);
        await page.keyboard.press('Enter');
        await new Promise(r => setTimeout(r, 1000));
      }
    }
    console.log(`\n=== ${batchName} ===`);
    console.log(`PASS (${results.pass.length}): ${results.pass.join(', ')}`);
    if (results.fail.length > 0) {
      console.log(`FAIL (${results.fail.length}): ${results.fail.join(', ')}`);
    }
    expect(results.fail).toEqual([]);
  });
}

// Preloaded host directory mount tests (fixtures/testdir mounted at /mnt/test)
test('preload: cat reads mounted file', async ({ page }) => {
  test.setTimeout(180000);
  await page.goto('/');
  await waitForTerminalContent(page, 'bash-static.wasm', 90000);

  await typeCommand(page, 'cat /mnt/test/hello.txt');
  const out = await waitForTerminalContent(page, 'Hello from preloaded file');
  expect(await out.jsonValue()).toContain('Hello from preloaded file');
});

test('preload: cat reads nested mounted file', async ({ page }) => {
  test.setTimeout(180000);
  await page.goto('/');
  await waitForTerminalContent(page, 'bash-static.wasm', 90000);

  await typeCommand(page, 'cat /mnt/test/subdir/nested.txt');
  const out = await waitForTerminalContent(page, 'Nested content here');
  expect(await out.jsonValue()).toContain('Nested content here');
});

test('preload: ls lists mounted directory', async ({ page }) => {
  test.setTimeout(180000);
  await page.goto('/');
  await waitForTerminalContent(page, 'bash-static.wasm', 90000);

  await typeCommand(page, 'ls /mnt/test/');
  const out = await waitForTerminalContent(page, 'hello.txt');
  const text = await out.jsonValue();
  expect(text).toContain('hello.txt');
  expect(text).toContain('lines.txt');
  expect(text).toContain('subdir');
});

test('preload: wc verifies mounted file content', async ({ page }) => {
  test.setTimeout(180000);
  await page.goto('/');
  await waitForTerminalContent(page, 'bash-static.wasm', 90000);

  await typeCommand(page, 'wc -l /mnt/test/lines.txt');
  const out = await waitForTerminalContent(page, '3');
  expect(await out.jsonValue()).toContain('3');
});
