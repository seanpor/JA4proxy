import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('should display login page', async ({ page }) => {
    await expect(page).toHaveTitle(/JA4 Proxy Management/);
    await expect(page.getByLabel('API Key')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible();
  });

  test('should show error for invalid API key', async ({ page }) => {
    await page.getByLabel('API Key').fill('invalid-key');
    await page.getByRole('button', { name: 'Sign In' }).click();

    await expect(page.getByText('Invalid API key. Please try again.')).toBeVisible();
    await expect(page).toHaveURL('/login');
  });

  test('should redirect to dashboard on successful login', async ({ page }) => {
    // In a real test, you would use a valid API key
    // For now, we'll mock this behavior
    await page.route('**/health/ready', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'healthy' }),
      });
    });

    await page.getByLabel('API Key').fill('valid-test-key');
    await page.getByRole('button', { name: 'Sign In' }).click();

    await expect(page).toHaveURL('/dashboard');
    await expect(page.getByText('Dashboard')).toBeVisible();
  });

  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL('/login');
  });
});