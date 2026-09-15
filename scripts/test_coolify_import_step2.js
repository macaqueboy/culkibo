const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.goto('http://localhost:3030');
  await page.waitForTimeout(800);
  await page.click('button:has-text("Importar desde Coolify")');
  await page.waitForTimeout(500);

  // Clear and fill URL
  const urlInput = page.locator('input[type="text"]').last();
  await urlInput.fill('https://hub.galeia.top');

  // Fill Token
  const tokenInput = page.locator('input[type="password"]');
  await tokenInput.fill('33|H9iZ5Hs4UJW3CrWMFvVpkDc5GPgi0Z8vwUQDPcpH42580f91');
  await page.waitForTimeout(300);

  // Click Connect
  await page.click('button:has-text("Conectar y Previsualizar")');

  // Wait for Step 2
  await page.waitForSelector('text=Aplicaciones Web', { timeout: 20000 });
  await page.waitForTimeout(1000);

  await page.screenshot({ path: 'screenshot_coolify_step2.png' });
  console.log('✓ screenshot_coolify_step2.png guardada con éxito');
  await browser.close();
})();
