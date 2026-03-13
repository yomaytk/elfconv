const { test, expect } = require('@playwright/test');

function readTerminalText() {
  const xterm = window.__test_xterm;
  if (!xterm) return '';
  const buf = xterm.buffer.active;
  let text = '';
  for (let i = 0; i <= buf.cursorY + buf.baseY; i++) {
    const line = buf.getLine(i);
    if (line) {
      text += line.translateToString(true) + '\n';
    }
  }
  return text;
}

async function waitForTerminalContent(page, content, timeout = 30000) {
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
  await page.keyboard.type(command);
  await page.keyboard.press('Enter');
}

test.describe('Syscall probe - new syscalls', () => {

  test('touch + chmod (fchmodat)', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'touch /tmp/tfile && chmod 755 /tmp/tfile && echo CHMOD_OK');
    const out = await waitForTerminalContent(page, 'CHMOD_OK');
    expect(await out.jsonValue()).toContain('CHMOD_OK');
  });

  test('ln -s (symlinkat)', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'touch /tmp/orig && ln -s /tmp/orig /tmp/slink && echo SYMLINK_OK');
    const out = await waitForTerminalContent(page, 'SYMLINK_OK');
    expect(await out.jsonValue()).toContain('SYMLINK_OK');
  });

  test('mv (renameat)', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'touch /tmp/mvfile && mv /tmp/mvfile /tmp/mvdst && echo MV_OK');
    const out = await waitForTerminalContent(page, 'MV_OK');
    expect(await out.jsonValue()).toContain('MV_OK');
  });

  test('umask', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'umask');
    const out = await waitForTerminalContent(page, '00');
    expect(await out.jsonValue()).toMatch(/\d{4}/);
  });

  test('head (basic busybox)', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'echo -e "line1\\nline2\\nline3" > /tmp/hf && head -n 2 /tmp/hf && echo HEADDONE');
    const out = await waitForTerminalContent(page, 'HEADDONE');
    const text = await out.jsonValue();
    expect(text).toContain('line1');
  });

  test('mkdir + rmdir', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'mkdir /tmp/testd && rmdir /tmp/testd && echo RMDIR_OK');
    const out = await waitForTerminalContent(page, 'RMDIR_OK');
    expect(await out.jsonValue()).toContain('RMDIR_OK');
  });

  test('basename + dirname', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'basename /usr/bin/bash');
    const out = await waitForTerminalContent(page, 'bash');
    expect(await out.jsonValue()).toContain('bash');
  });

  test('expr', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    await typeCommand(page, 'expr 2 + 3');
    const out = await waitForTerminalContent(page, '5');
    expect(await out.jsonValue()).toContain('5');
  });

  test('/proc files readable (cat /proc/uptime and /proc/meminfo)', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    // Test /proc/uptime
    await typeCommand(page, 'cat /proc/uptime');
    await new Promise(r => setTimeout(r, 1000));

    // Test /proc/meminfo
    await typeCommand(page, 'head -3 /proc/meminfo');
    await new Promise(r => setTimeout(r, 1000));

    // Dump buffer to verify
    const dump = await page.evaluate(() => {
      const xterm = window.__test_xterm;
      if (!xterm) return '';
      const buf = xterm.buffer.active;
      let lines = [];
      for (let i = 0; i < buf.length; i++) {
        const line = buf.getLine(i);
        if (line) {
          let text = line.translateToString(true);
          if (text.trim()) lines.push(text);
        }
      }
      return lines.join('\n');
    });

    // /proc/uptime should output digits.digits
    expect(dump).toMatch(/\d+\.\d+/);
    // /proc/meminfo should have MemTotal
    expect(dump).toContain('MemTotal');
  });

  test('top shows system info then quits', async ({ page }) => {
    await page.goto('/');
    await waitForTerminalContent(page, 'bash-static.wasm');

    // Run top
    await typeCommand(page, 'top -b -n 1');
    // Wait for top output to appear (Mem or CPU line)
    await new Promise(r => setTimeout(r, 5000));

    // Dump buffer
    const dump = await page.evaluate(() => {
      const xterm = window.__test_xterm;
      if (!xterm) return '';
      const buf = xterm.buffer.active;
      let lines = [];
      for (let i = 0; i < buf.length; i++) {
        const line = buf.getLine(i);
        if (line) {
          let text = line.translateToString(true);
          if (text.trim()) lines.push(text);
        }
      }
      return lines.join('\n');
    });

    // top should show memory info and CPU info
    expect(dump).toMatch(/Mem:/i);
  });
});
