import React, { useState } from 'react';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Switch } from '../components/ui/Switch';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, Save, Settings, Shield, Network, Fingerprint } from 'lucide-react';

export const ConfigPage: React.FC = () => {
  const [formData, setFormData] = useState({
    api_key: '',
    redis_url: 'redis://localhost:6379',
    debug_mode: false,
    auto_update: true,
    max_connections: 1000,
    rate_limit: 100,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? (e.target as HTMLInputElement).checked : value,
    }));
  };

  const handleSwitchChange = (name: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      [name]: checked,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(false);

    try {
      // In a real implementation, this would call an API endpoint
      // await updateConfig(formData);
      console.log('Configuration saved:', formData);
      setSubmitSuccess(true);
      setTimeout(() => setSubmitSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to update config:', err);
      setSubmitError('Failed to update configuration. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">System Configuration</h1>
      </div>

      {submitError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{submitError}</AlertDescription>
        </Alert>
      )}

      {submitSuccess && (
        <Alert variant="success">
          <Settings className="h-4 w-4" />
          <AlertDescription>Configuration updated successfully!</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>General Settings</CardTitle>
          <CardDescription>
            Configure the basic system parameters
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="redis_url">Redis Connection URL</Label>
                <Input
                  id="redis_url"
                  name="redis_url"
                  value={formData.redis_url}
                  onChange={handleInputChange}
                  placeholder="redis://localhost:6379"
                />
                <p className="text-sm text-muted-foreground">
                  URL for Redis database connection
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="max_connections">Max Connections</Label>
                <Input
                  id="max_connections"
                  name="max_connections"
                  type="number"
                  min="10"
                  max="10000"
                  value={formData.max_connections}
                  onChange={handleInputChange}
                />
                <p className="text-sm text-muted-foreground">
                  Maximum concurrent connections allowed
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="rate_limit">Rate Limit (req/min)</Label>
                <Input
                  id="rate_limit"
                  name="rate_limit"
                  type="number"
                  min="10"
                  max="10000"
                  value={formData.rate_limit}
                  onChange={handleInputChange}
                />
                <p className="text-sm text-muted-foreground">
                  API rate limit in requests per minute
                </p>
              </div>

              <div className="flex items-center space-x-2 pt-4">
                <Switch
                  id="debug_mode"
                  name="debug_mode"
                  checked={formData.debug_mode}
                  onCheckedChange={(checked) => handleSwitchChange('debug_mode', checked)}
                />
                <Label htmlFor="debug_mode">Debug Mode</Label>
                <p className="text-sm text-muted-foreground ml-auto">
                  Enable verbose logging and debugging
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="auto_update"
                  name="auto_update"
                  checked={formData.auto_update}
                  onCheckedChange={(checked) => handleSwitchChange('auto_update', checked)}
                />
                <Label htmlFor="auto_update">Auto Update</Label>
                <p className="text-sm text-muted-foreground ml-auto">
                  Automatically check for and apply updates
                </p>
              </div>

              <div className="pt-4 border-t">
                <Button type="submit" disabled={isSubmitting}>
                  <Save className="h-4 w-4 mr-2" />
                  {isSubmitting ? 'Saving...' : 'Save Configuration'}
                </Button>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security Settings</CardTitle>
          <CardDescription>
            Configure security-related parameters
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="api_key">API Key</Label>
            <div className="flex gap-2">
              <Input
                id="api_key"
                name="api_key"
                type="password"
                value={formData.api_key}
                onChange={handleInputChange}
                placeholder="Generate or paste API key"
              />
              <Button variant="secondary" type="button">
                Generate
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              API key for management interface access
            </p>
          </div>

          <div className="space-y-4 pt-4">
            <div className="flex items-center justify-between py-2 border-b">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span>IP Ban Duration</span>
              </div>
              <span className="font-mono">24 hours</span>
            </div>

            <div className="flex items-center justify-between py-2 border-b">
              <div className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                <span>Allowed CIDR Ranges</span>
              </div>
              <span className="font-mono">5 configured</span>
            </div>

            <div className="flex items-center justify-between py-2 border-b">
              <div className="flex items-center gap-2">
                <Fingerprint className="h-4 w-4" />
                <span>Blocked Fingerprints</span>
              </div>
              <span className="font-mono">12 configured</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Advanced Settings</CardTitle>
          <CardDescription>
            Advanced configuration options
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Alert variant="warning">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                These settings should only be modified if you understand their impact on system performance and security.
              </AlertDescription>
            </Alert>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="worker_threads">Worker Threads</Label>
                <Input
                  id="worker_threads"
                  name="worker_threads"
                  type="number"
                  min="1"
                  max="32"
                  defaultValue="4"
                />
                <p className="text-sm text-muted-foreground">
                  Number of worker threads for processing
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="cache_ttl">Cache TTL (seconds)</Label>
                <Input
                  id="cache_ttl"
                  name="cache_ttl"
                  type="number"
                  min="60"
                  max="86400"
                  defaultValue="300"
                />
                <p className="text-sm text-muted-foreground">
                  Time-to-live for cached data
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};