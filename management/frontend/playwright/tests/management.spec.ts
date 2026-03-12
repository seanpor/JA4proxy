import { test, expect } from '@playwright/test';

test.describe('Management Operations', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authentication
    await page.route('**/health/ready', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'healthy' }),
      });
    });

    // Mock API responses
    await page.route('**/bans', route => {
      if (route.request().method() === 'GET') {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      } else {
        route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ id: '1', ip: '192.168.1.1', reason: 'test', expires_at: '2023-12-31T00:00:00Z' }),
        });
      }
    });

    await page.route('**/cidrs', route => {
      if (route.request().method() === 'GET') {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      } else {
        route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ id: '1', cidr: '192.168.1.0/24', reason: 'test' }),
        });
      }
    });

    await page.route('**/fingerprints', route => {
      if (route.request().method() === 'GET') {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      } else {
        route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ id: '1', fingerprint: 'test-fingerprint', tag: 'test' }),
        });
      }
    });

    // Set API key in sessionStorage
    await page.goto('/login');
    await page.evaluate(() => {
      sessionStorage.setItem('ja4proxy_api_key', 'test-key');
    });
  });

  test('should create and manage bans', async ({ page }) => {
    await page.goto('/bans');

    // Open create ban dialog
    await page.getByRole('button', { name: 'Add Ban' }).click();

    // Fill ban form
    await page.getByLabel('IP Address').fill('192.168.1.100');
    await page.getByLabel('Reason').fill('Test ban');
    await page.getByLabel('Expiration Date').fill('2023-12-31T00:00');

    // Submit form
    await page.getByRole('button', { name: 'Create Ban' }).click();

    // Verify ban was created (in a real test, this would check the API response)
    await expect(page.getByText('Test ban')).toBeVisible();
  });

  test('should create and manage CIDR blocks', async ({ page }) => {
    await page.goto('/cidrs');

    // Open create CIDR dialog
    await page.getByRole('button', { name: 'Add CIDR' }).click();

    // Fill CIDR form
    await page.getByLabel('CIDR Notation').fill('192.168.1.0/24');
    await page.getByLabel('Reason').fill('Test CIDR block');

    // Submit form
    await page.getByRole('button', { name: 'Create CIDR Block' }).click();

    // Verify CIDR was created
    await expect(page.getByText('192.168.1.0/24')).toBeVisible();
  });

  test('should create and manage fingerprints', async ({ page }) => {
    await page.goto('/fingerprints');

    // Open create fingerprint dialog
    await page.getByRole('button', { name: 'Add Fingerprint' }).click();

    // Fill fingerprint form
    await page.getByLabel('Fingerprint Hash').fill('771a332b45a32e3b8c4d5e6f7a8b9c0d');
    await page.getByLabel('Tag').fill('test-fingerprint');

    // Submit form
    await page.getByRole('button', { name: 'Create Fingerprint' }).click();

    // Verify fingerprint was created
    await expect(page.getByText('771a332b45a32e3b8c4d5e6f7a8b9c0d')).toBeVisible();
  });

  test('should test counterfactual fingerprint', async ({ page }) => {
    await page.goto('/dial');

    // Mock dial endpoint
    await page.route('**/dial', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          decision: 'block',
          rules_matched: [{ name: 'test-rule' }],
          additional_data: { score: 0.95 }
        }),
      });
    });

    // Fill fingerprint and test
    await page.getByLabel('TLS Fingerprint').fill('771a332b45a32e3b8c4d5e6f7a8b9c0d');
    await page.getByRole('button', { name: 'Test Fingerprint' }).click();

    // Verify results
    await expect(page.getByText('block')).toBeVisible();
    await expect(page.getByText('test-rule')).toBeVisible();
  });

  test('should update policy configuration', async ({ page }) => {
    await page.goto('/policy');

    // Mock config endpoint
    await page.route('**/config/thresholds', route => {
      if (route.request().method() === 'GET') {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ban_threshold: 10,
            fingerprint_threshold: 5,
            cidr_threshold: 3
          }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(route.request().postDataJSON()),
        });
      }
    });

    // Update thresholds
    await page.getByLabel('Ban Threshold').fill('15');
    await page.getByLabel('Fingerprint Threshold').fill('8');
    await page.getByLabel('CIDR Threshold').fill('5');

    // Save configuration
    await page.getByRole('button', { name: 'Save Configuration' }).click();

    // Verify success message
    await expect(page.getByText('Configuration updated successfully!')).toBeVisible();
  });
});