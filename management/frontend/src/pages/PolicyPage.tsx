import React, { useState } from 'react';
import { useThresholdConfig } from '../hooks/useApi';
import { Button, Card, CardHeader, CardTitle, CardContent, CardDescription, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Save, Shield } from 'lucide-react';

export const PolicyPage: React.FC = () => {
  const { data: config, isLoading, error, updateThresholdConfig } = useThresholdConfig();
  const [formData, setFormData] = useState({
    flag: config?.flag ?? 20,
    rate_limit: config?.rate_limit ?? 35,
    tarpit: config?.tarpit ?? 55,
    block: config?.block ?? 70,
    ban: config?.ban ?? 85,
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);

  // Update form data when config loads
  React.useEffect(() => {
    if (config) {
      setFormData({
        flag: config.flag,
        rate_limit: config.rate_limit,
        tarpit: config.tarpit,
        block: config.block,
        ban: config.ban,
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
      setSubmitError('Failed to update configuration. Thresholds must be in ascending order: flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const thresholdFields: { key: keyof typeof formData; label: string; description: string }[] = [
    { key: 'flag', label: 'Flag (score ≥)', description: 'Score to flag a connection for review' },
    { key: 'rate_limit', label: 'Rate Limit (score ≥)', description: 'Score to apply rate limiting' },
    { key: 'tarpit', label: 'Tarpit (score ≥)', description: 'Score to tarpit the connection' },
    { key: 'block', label: 'Block (score ≥)', description: 'Score to block the connection' },
    { key: 'ban', label: 'Ban (score ≥)', description: 'Score to ban the IP address' },
  ];

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
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertDescription>Configuration updated successfully!</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Risk Score Thresholds</CardTitle>
          <CardDescription>
            Connections are scored 0–100. Each threshold triggers an action when the score meets or exceeds it.
            Thresholds must be in ascending order.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading configuration...</div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {thresholdFields.map(({ key, label, description }) => (
                  <div key={key} className="space-y-2">
                    <Label htmlFor={key}>{label}</Label>
                    <Input
                      id={key}
                      name={key}
                      type="number"
                      min="0"
                      max="100"
                      value={formData[key]}
                      onChange={handleInputChange}
                    />
                    <p className="text-xs text-muted-foreground">{description}</p>
                  </div>
                ))}
              </div>

              <div className="pt-4 border-t">
                <Button type="submit" disabled={isSubmitting}>
                  <Save className="h-4 w-4 mr-2" />
                  {isSubmitting ? 'Saving...' : 'Save Thresholds'}
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Current Thresholds Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {thresholdFields.map(({ key, label }) => (
              <div key={key} className="flex justify-between items-center py-2 border-b last:border-0">
                <span className="text-sm">{label}</span>
                <span className="font-mono font-semibold">{formData[key]}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
