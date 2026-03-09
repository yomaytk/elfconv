const { test, expect } = require('@playwright/test');

test('hello world ELF runs correctly in browser', async ({ page }) => {
  const consoleLogs = [];
  page.on('console', msg => consoleLogs.push(`[${msg.type()}] ${msg.text()}`));
  page.on('pageerror', err => consoleLogs.push(`PAGE ERROR: ${err.message}`));

  await page.goto('/');

  const output = await page.waitForFunction(() => {
    const xterm = window.__test_xterm;
    if (!xterm) return false;
    const buf = xterm.buffer.active;
    let text = '';
    for (let i = 0; i <= buf.cursorY + buf.baseY; i++) {
      const line = buf.getLine(i);
      if (line) {
        text += line.translateToString(true) + '\n';
      }
    }
    if (text.includes('Hello, World!')) return text;
    return false;
  }, null, { timeout: 30000 });

  const text = await output.jsonValue();
  console.log(`Terminal output: "${text.trim()}"`);
  expect(text).toContain('Hello, World!');
});
