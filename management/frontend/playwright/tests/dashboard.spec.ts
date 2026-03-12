import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication
    await page.route('**/health/ready', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'healthy' }),
      });
    });

    // Set API key in sessionStorage
    await page.goto('/login');
    await page.evaluate(() => {
      sessionStorage.setItem('ja4proxy_api_key', 'test-key');
    });
    await page.goto('/dashboard');
  });

  test('should display dashboard with metrics', async ({ page }) => {
    await expect(page).toHaveURL('/dashboard');
    await expect(page.getByText('Dashboard')).toBeVisible();

    // Check metric cards
    await expect(page.getByText('Active Bans')).toBeVisible();
    await expect(page.getByText('CIDR Blocks')).toBeVisible();
    await expect(page.getByText('Fingerprints')).toBeVisible();
    await expect(page.getByText('System Health')).toBeVisible();
  });

  test('should show recent events section', async ({ page }) => {
    await expect(page.getByText('Recent Events')).toBeVisible();
    await expect(page.getByRole('table')).toBeVisible();
  });

  test('should show system status section', async ({ page }) => {
    await expect(page.getByText('System Status')).toBeVisible();
    await expect(page.getByText('Uptime')).toBeVisible();
    await expect(page.getByText('Redis Connection')).toBeVisible();
    await expect(page.getByText('Protection Status')).toBeVisible();
  });

  test('should navigate to other pages', async ({ page }) => {
    // Test navigation to Bans page
    await page.getByRole('link', { name: 'Bans' }).click();
    await expect(page).toHaveURL('/bans');
    await expect(page.getByText('Ban Management')).toBeVisible();

    // Test navigation back to dashboard
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL('/dashboard');
  });
});