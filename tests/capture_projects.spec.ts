import { test, expect } from '@playwright/test';

test('capture projects', async ({ page }) => {
  await page.goto('http://localhost:5173');
  await page.waitForTimeout(3000); // Wait for projects to load
  await page.screenshot({ path: 'screenshot_projects_fixed.png', fullPage: true });
});

