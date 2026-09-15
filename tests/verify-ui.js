const { chromium } = require('playwright');
const path = require('path');

async function main() {
  console.log('🎭 Running Interactive Playwright Verification...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 950 } });
  const page = await context.newPage();

  console.log('Navigating to http://localhost:3030 ...');
  await page.goto('http://localhost:3030', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);

  // 1. Click "Activar" on the first card (CALEKI)
  const activarBtn = page.getByRole('button', { name: 'Activar' }).first();
  console.log('Clicking "Activar" on first project...');
  await activarBtn.click();
  await page.waitForTimeout(1500);

  // Take screenshot of list with active project
  await page.screenshot({ path: path.join(__dirname, '..', 'screenshot_list_active.png'), fullPage: true });
  console.log('✓ Captured screenshot_list_active.png');

  // Verify "Detener" button is now visible on that card
  const detenerBtn = page.getByRole('button', { name: 'Detener' }).first();
  console.log('Checking "Detener" button presence:', await detenerBtn.isVisible());

  // Click on "Detalles" of CALEKI to check Detail view when Active
  await page.getByText('Detalles').first().click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(__dirname, '..', 'screenshot_detail_active.png'), fullPage: true });
  console.log('✓ Captured screenshot_detail_active.png');

  // 2. Click "Detener" from ProjectDetail
  const stopDetailBtn = page.getByRole('button', { name: 'Detener' });
  console.log('Clicking "Detener" from inside ProjectDetail...');
  await stopDetailBtn.click();
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(__dirname, '..', 'screenshot_detail_stopped.png'), fullPage: true });
  console.log('✓ Captured screenshot_detail_stopped.png');

  // Go back to list and verify it is stopped
  await page.getByText('← Volver').click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(__dirname, '..', 'screenshot_list_stopped_again.png'), fullPage: true });
  console.log('✓ Captured screenshot_list_stopped_again.png');

  await browser.close();
  console.log('✅ Interactive verification completed successfully!');
}

main().catch(err => {
  console.error('❌ Interactive verification failed:', err);
  process.exit(1);
});
