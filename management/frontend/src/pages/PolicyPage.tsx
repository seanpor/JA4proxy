import React, { useState } from 'react';
import { useThresholdConfig } from '../hooks/useApi';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, Save, Shield, Fingerprint, Network } from 'lucide-react';

export const PolicyPage: React.FC = () => {
  const { data: config, isLoading, error, updateThresholdConfig } = useThresholdConfig();
  const [formData, setFormData] = useState({
    ban_threshold: config?.ban_threshold || 10,
    fingerprint_threshold: config?.fingerprint_threshold || 5,
    cidr_threshold: config?.cidr_threshold || 3,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  // Update form data when config loads
  React.useEffect(() => {
    if (config) {
      setFormData({
        ban_threshold: config.ban_threshold,
        fingerprint_threshold: config.fingerprint_threshold,
        cidr_threshold: config.cidr_threshold,
      });
    }
  }, [config]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: parseInt(value) || 0,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(false);

    try {
      await updateThresholdConfig(formData);
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
        <h1 className="text-2xl font-bold">Policy Configuration</h1>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load configuration: {error.message}</AlertDescription>
        </Alert>
      )}

      {submitError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{submitError}</AlertDescription>
        </Alert>
      )}

      {submitSuccess && (
        <Alert variant="success">
          <Shield className="h-4 w-4" />
          <AlertDescription>Configuration updated successfully!</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Threshold Configuration</CardTitle>
          <CardDescription>
            Configure the detection thresholds for automatic blocking
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading configuration...</div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="ban_threshold">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        <span>Ban Threshold</span>
                      </div>
                    </Label>
                    <Input
                      id="ban_threshold"
                      name="ban_threshold"
                      type="number"
                      min="1"
                      value={formData.ban_threshold}
                      onChange={handleInputChange}
                    />
                    <p className="text-sm text-muted-foreground">
                      Number of detections before automatic IP ban
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="fingerprint_threshold">
                      <div className="flex items-center gap-2">
                        <Fingerprint className="h-4 w-4" />
                        <span>Fingerprint Threshold</span>
                      </div>
                    </Label>
                    <Input
                      id="fingerprint_threshold"
                      name="fingerprint_threshold"
                      type="number"
                      min="1"
                      value={formData.fingerprint_threshold}
                      onChange={handleInputChange}
                    />
                    <p className="text-sm text-muted-foreground">
                      Number of fingerprint matches before action
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="cidr_threshold">
                      <div className="flex items-center gap-2">
                        <Network className="h-4 w-4" />
                        <span>CIDR Threshold</span>
                      </div>
                    </Label>
                    <Input
                      id="cidr_threshold"
                      name="cidr_threshold"
                      type="number"
                      min="1"
                      value={formData.cidr_threshold}
                      onChange={handleInputChange}
                    />
                    <p className="text-sm text-muted-foreground">
                      Number of CIDR matches before blocking
                    </p>
                  </div>
                </div>

                <div className="pt-4 border-t">
                  <Button type="submit" disabled={isSubmitting}>
                    <Save className="h-4 w-4 mr-2" />
                    {isSubmitting ? 'Saving...' : 'Save Configuration'}
                  </Button>
                </div>
              </div>
            </form>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Current Policy Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span>Automatic Bans</span>
              </div>
              <span className="font-mono">{formData.ban_threshold} detections</span>
            </div>

            <div className="flex justify-between items-center py-2 border-b">
              <div className="flex items-center gap-2">
                <Fingerprint className="h-4 w-4" />
                <span>Fingerprint Detection</span>
              </div>
              <span className="font-mono">{formData.fingerprint_threshold} matches</span>
            </div>

            <div className="flex justify-between items-center py-2 border-b">
              <div className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                <span>CIDR Blocking</span>
              </div>
              <span className="font-mono">{formData.cidr_threshold} matches</span>
            </div>
          </div>

          <div className="mt-6 p-4 bg-muted rounded-lg">
            <h3 className="font-semibold mb-2">Policy Behavior</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>IP addresses will be automatically banned after {formData.ban_threshold} malicious detections</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>TLS fingerprints will trigger actions after {formData.fingerprint_threshold} matches</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-1">•</span>
                <span>CIDR blocks will be applied after {formData.cidr_threshold} network matches</span>
              </li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};