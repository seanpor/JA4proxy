import React, { useState } from 'react';
import { useDial } from '../hooks/useApi';
import { apiClient } from '../api/client';
import { Button, Card, CardHeader, CardTitle, CardContent, CardDescription, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Shield, CheckCircle } from 'lucide-react';

export const DialPage: React.FC = () => {
  const { data: dialData, isLoading, error, setDial } = useDial();
  const [dialValue, setDialValue] = useState<number>(0);
  const [reason, setReason] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [isAcknowledging, setIsAcknowledging] = useState(false);

  React.useEffect(() => {
    if (dialData) {
      setDialValue(dialData.dial);
    }
  }, [dialData]);

  const handleAcknowledge = async () => {
    setIsAcknowledging(true);
    setSubmitError(null);
    try {
      await apiClient.post('/dial/acknowledge', { acknowledged: true });
      window.location.reload();
    } catch (err: any) {
      setSubmitError(err?.response?.data?.detail ?? 'Failed to acknowledge');
    } finally {
      setIsAcknowledging(false);
    }
  };

  const handleSetDial = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(false);

    try {
      await apiClient.put('/dial', { dial: dialValue, reason });
      setSubmitSuccess(true);
      setReason('');
      setTimeout(() => setSubmitSuccess(false), 3000);
    } catch (err: any) {
      setSubmitError(err?.response?.data?.detail ?? 'Failed to update dial');
    } finally {
      setIsSubmitting(false);
    }
  };

  const dialDescription = (v: number) => {
    if (v === 0) return 'Monitor only — no connections blocked';
    if (v <= 25) return 'Low — only very high-confidence threats blocked';
    if (v <= 50) return 'Medium — moderate threat level required to block';
    if (v <= 75) return 'High — aggressive blocking';
    return 'Maximum — strictest blocking';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Blocking Dial</h1>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load dial: {error.message}</AlertDescription>
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
          <CheckCircle className="h-4 w-4" />
          <AlertDescription>Dial updated successfully.</AlertDescription>
        </Alert>
      )}

      {isLoading ? (
        <div className="text-center py-8">Loading...</div>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Current Dial Setting</CardTitle>
              <CardDescription>
                The dial controls how aggressively the proxy blocks traffic. 0 = monitor only, 100 = maximum blocking.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-5xl font-bold text-center py-4">
                {dialData?.dial ?? 0}
                <span className="text-lg text-muted-foreground"> / 100</span>
              </div>
              <p className="text-center text-muted-foreground">{dialDescription(dialData?.dial ?? 0)}</p>

              {dialData?.blocking_acknowledged === false && dialData?.dial === 0 && (
                <Alert className="mt-4">
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    Blocking is not acknowledged. Acknowledge below before raising the dial above 0.
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          {!dialData?.blocking_acknowledged && (
            <Card>
              <CardHeader>
                <CardTitle>Acknowledge Blocking Risk</CardTitle>
                <CardDescription>
                  You must acknowledge that raising the dial above 0 will block real connections before proceeding.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button onClick={handleAcknowledge} disabled={isAcknowledging}>
                  <Shield className="h-4 w-4 mr-2" />
                  {isAcknowledging ? 'Acknowledging...' : 'I understand — enable blocking'}
                </Button>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Update Dial</CardTitle>
              <CardDescription>
                Set the dial to 0 at any time to return to monitor-only mode immediately.
                Changes above 0 require acknowledgment and are rate-limited (max 10/hour).
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSetDial} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="dial-value">Dial Value (0–100)</Label>
                  <Input
                    id="dial-value"
                    type="number"
                    min={0}
                    max={100}
                    value={dialValue}
                    onChange={(e) => setDialValue(parseInt(e.target.value) || 0)}
                    className="w-32"
                  />
                  <p className="text-sm text-muted-foreground">{dialDescription(dialValue)}</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="reason">Reason (optional)</Label>
                  <Input
                    id="reason"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="e.g., Responding to active attack campaign"
                  />
                </div>
                <Button
                  type="submit"
                  disabled={isSubmitting || (dialValue > 0 && !dialData?.blocking_acknowledged)}
                >
                  {isSubmitting ? 'Updating...' : 'Set Dial'}
                </Button>
              </form>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};
