const { test, expect } = require('@playwright/test');

// This function is serialized and executed inside the browser context via waitForFunction.
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

async function waitForTerminalContent(page, content, timeout = 90000) {
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

test.describe('Bash + Busybox browser tests', () => {

  test.beforeEach(async ({ page }) => {
    page.on('console', msg => {
      if (msg.type() === 'error') {
        console.log(`[browser error] ${msg.text()}`);
      }
    });
    page.on('pageerror', err => console.log(`PAGE ERROR: ${err.message}`));
  });

  test('bash starts and shows prompt', async ({ page }) => {
    await page.goto('/');

    const output = await waitForTerminalContent(page, 'bash-static.wasm');
    const text = await output.jsonValue();
    expect(text).toContain('bash-static.wasm');
  });

  test('uname -a returns expected output', async ({ page }) => {
    await page.goto('/');

    await waitForTerminalContent(page, 'bash-static.wasm');
    await typeCommand(page, 'uname -a');

    const output = await waitForTerminalContent(page, 'wasm32 GNU/Linux');
    const text = await output.jsonValue();

    expect(text).toContain('Linux');
    expect(text).toContain('wasm-host-01');
    expect(text).toContain('wasm32 GNU/Linux');
  });

  test('ls shows filesystem directories', async ({ page }) => {
    await page.goto('/');

    await waitForTerminalContent(page, 'bash-static.wasm');
    await typeCommand(page, 'ls');

    const output = await waitForTerminalContent(page, 'dev');
    const text = await output.jsonValue();

    expect(text).toContain('dev');
    expect(text).toContain('home');
    expect(text).toContain('proc');
    expect(text).toContain('tmp');
    expect(text).toContain('usr');
  });
});
