const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  await page.goto('http://localhost:3030').catch(() => console.log('goto failed'));
  await page.waitForTimeout(2000);

  // Click on the first project in the grid
  await page.locator('.bg-white.border.border-slate-200.rounded-2xl.p-5.shadow-sm').first().click().catch(e => console.log('click failed', e));
  await page.waitForTimeout(1000);

  // General tab screenshot
  await page.screenshot({ path: 'screenshot_project_general.png', fullPage: true });

  // Click on Logs tab
  await page.getByText('Logs', { exact: true }).first().click().catch(() => {});
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'screenshot_project_logs.png', fullPage: true });

  // Click on Variables tab
  await page.getByText('Variables', { exact: true }).first().click().catch(() => {});
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'screenshot_project_vars.png', fullPage: true });

  await browser.close();
})();
