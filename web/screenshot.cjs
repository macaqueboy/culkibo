const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  await page.goto('http://localhost:3030');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: 'screenshot_pods.png', fullPage: true });

  const tabs = [
    { text: 'Dominios & Cloudflare', name: 'domains' },
    { text: 'Conectar con la IA', name: 'mcp' },
    { text: 'Actividad en Vivo', name: 'logs' },
    { text: 'Configuración', name: 'settings' }
  ];
  
  for (const tab of tabs) {
    await page.getByText(tab.text, { exact: true }).first().click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: `screenshot_${tab.name}.png`, fullPage: true });
  }

  await browser.close();
})();
