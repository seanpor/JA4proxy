import React, { useState } from 'react';
import { useDial } from '../hooks/useApi';
import { apiClient } from '../api/client';
import { Button, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Shield, CheckCircle, Activity } from 'lucide-react';

const dialLabel = (v: number) => {
  if (v === 0) return { text: 'Monitor only', color: 'text-green-600', bg: 'bg-green-50' };
  if (v <= 25) return { text: 'Low blocking', color: 'text-blue-600', bg: 'bg-blue-50' };
  if (v <= 50) return { text: 'Medium blocking', color: 'text-yellow-600', bg: 'bg-yellow-50' };
  if (v <= 75) return { text: 'High blocking', color: 'text-orange-600', bg: 'bg-orange-50' };
  return { text: 'Maximum blocking', color: 'text-red-600', bg: 'bg-red-50' };
};

export const DialPage: React.FC = () => {
  const { data: dialData, isLoading, error, setDial } = useDial();
  const [dialValue, setDialValue] = useState<number>(0);
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAcknowledging, setIsAcknowledging] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  React.useEffect(() => {
    if (dialData) setDialValue(dialData.dial);
  }, [dialData]);

  const handleAcknowledge = async () => {
    setIsAcknowledging(true);
    setFeedback(null);
    try {
      await apiClient.post('/dial/acknowledge', { acknowledged: true });
      window.location.reload();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.response?.data?.detail ?? 'Failed to acknowledge' });
    } finally {
      setIsAcknowledging(false);
    }
  };

  const handleSetDial = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setFeedback(null);
    try {
      await apiClient.put('/dial', { dial: dialValue, reason });
      setFeedback({ type: 'success', message: `Dial set to ${dialValue}` });
      setReason('');
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.response?.data?.detail ?? 'Failed to update dial' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const current = dialData?.dial ?? 0;
  const label = dialLabel(current);
  const newLabel = dialLabel(dialValue);

  return (
    <div className="flex flex-col h-full">
      <div className="mb-4 flex-shrink-0">
        <h1 className="text-lg font-semibold text-gray-900">Blocking Dial</h1>
        <p className="text-xs text-gray-500 mt-0.5">0 = monitor only, 100 = maximum blocking</p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center flex-1 text-gray-400 text-sm">Loading…</div>
      ) : (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-3xl">
            {/* Current state */}
            <div className="bg-white rounded-lg border border-gray-200 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Activity className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-700">Current State</span>
              </div>
              <div className="text-center py-4">
                <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full ${label.bg} mb-3`}>
                  <span className={`text-4xl font-bold ${label.color}`}>{current}</span>
                </div>
                <p className={`text-sm font-medium ${label.color}`}>{label.text}</p>
                <p className="text-xs text-gray-400 mt-1">
                  {dialData?.blocking_acknowledged ? 'Blocking acknowledged' : 'Not acknowledged'}
                </p>
              </div>
            </div>

            {/* Controls */}
            <div className="bg-white rounded-lg border border-gray-200 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-700">Set Dial</span>
              </div>

              {!dialData?.blocking_acknowledged && (
                <div className="mb-4 p-3 rounded-lg bg-amber-50 border border-amber-200">
                  <p className="text-xs text-amber-700 mb-2">You must acknowledge blocking risk before raising the dial above 0.</p>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAcknowledge}
                    disabled={isAcknowledging}
                  >
                    {isAcknowledging ? 'Acknowledging…' : 'I understand — enable blocking'}
                  </Button>
                </div>
              )}

              <form onSubmit={handleSetDial} className="space-y-3">
                <div>
                  <Label htmlFor="dial-value">Dial value (0–100)</Label>
                  <div className="flex items-center gap-3 mt-1">
                    <Input
                      id="dial-value"
                      type="number"
                      min={0}
                      max={100}
                      value={dialValue}
                      onChange={e => setDialValue(parseInt(e.target.value) || 0)}
                      className="w-24"
                    />
                    <span className={`text-xs font-medium ${newLabel.color}`}>{newLabel.text}</span>
                  </div>
                </div>
                <div>
                  <Label htmlFor="reason">Reason (optional)</Label>
                  <Input
                    id="reason"
                    className="mt-1"
                    value={reason}
                    onChange={e => setReason(e.target.value)}
                    placeholder="e.g. Active attack campaign"
                  />
                </div>
                <Button
                  type="submit"
                  disabled={isSubmitting || (dialValue > 0 && !dialData?.blocking_acknowledged)}
                >
                  {isSubmitting ? 'Updating…' : 'Set Dial'}
                </Button>
              </form>
            </div>
          </div>

          {/* Feedback */}
          {(error || feedback) && (
            <div className="mt-4 max-w-3xl">
              {error && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" /><AlertDescription>{error.message}</AlertDescription>
                </Alert>
              )}
              {feedback?.type === 'error' && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" /><AlertDescription>{feedback.message}</AlertDescription>
                </Alert>
              )}
              {feedback?.type === 'success' && (
                <Alert variant="success">
                  <CheckCircle className="h-4 w-4" /><AlertDescription>{feedback.message}</AlertDescription>
                </Alert>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
