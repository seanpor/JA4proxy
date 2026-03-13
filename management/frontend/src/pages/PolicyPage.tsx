import React, { useState } from 'react';
import { useThresholdConfig } from '../hooks/useApi';
import { Button, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Save, CheckCircle } from 'lucide-react';

const FIELDS = [
  { key: 'flag' as const,       label: 'Flag',       color: 'text-blue-600',   bg: 'bg-blue-50' },
  { key: 'rate_limit' as const, label: 'Rate Limit', color: 'text-yellow-600', bg: 'bg-yellow-50' },
  { key: 'tarpit' as const,     label: 'Tarpit',     color: 'text-orange-600', bg: 'bg-orange-50' },
  { key: 'block' as const,      label: 'Block',      color: 'text-red-600',    bg: 'bg-red-50' },
  { key: 'ban' as const,        label: 'Ban',        color: 'text-red-900',    bg: 'bg-red-100' },
];

export const PolicyPage: React.FC = () => {
  const { data: config, isLoading, error, updateThresholdConfig } = useThresholdConfig();
  const [form, setForm] = useState({ flag: 20, rate_limit: 35, tarpit: 55, block: 70, ban: 85 });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  React.useEffect(() => {
    if (config) setForm({ flag: config.flag, rate_limit: config.rate_limit, tarpit: config.tarpit, block: config.block, ban: config.ban });
  }, [config]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setFeedback(null);
    try {
      await updateThresholdConfig(form);
      setFeedback({ type: 'success', message: 'Thresholds saved' });
      setTimeout(() => setFeedback(null), 3000);
    } catch {
      setFeedback({ type: 'error', message: 'Thresholds must be in ascending order: flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban' });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="mb-4 flex-shrink-0">
        <h1 className="text-lg font-semibold text-gray-900">Policy</h1>
        <p className="text-xs text-gray-500 mt-0.5">Risk score thresholds (0–100). Connections scoring at or above each threshold trigger that action.</p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center flex-1 text-gray-400 text-sm">Loading…</div>
      ) : (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <div className="bg-white rounded-lg border border-gray-200 p-5 max-w-3xl">
            {error && (
              <Alert variant="destructive" className="mb-4">
                <AlertCircle className="h-4 w-4" /><AlertDescription>{error.message}</AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmit}>
              {/* Visual threshold bar */}
              <div className="flex gap-1 h-6 rounded-full overflow-hidden mb-6">
                {FIELDS.map(({ key, bg }) => (
                  <div
                    key={key}
                    className={`flex-1 ${bg} flex items-center justify-center`}
                    title={`${form[key]}`}
                  />
                ))}
              </div>

              <div className="grid grid-cols-5 gap-4 mb-6">
                {FIELDS.map(({ key, label, color, bg }) => (
                  <div key={key} className="space-y-1">
                    <div className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${bg} ${color} mb-1`}>
                      {label}
                    </div>
                    <Input
                      type="number"
                      min={0}
                      max={100}
                      value={form[key]}
                      onChange={e => setForm(prev => ({ ...prev, [key]: parseInt(e.target.value) || 0 }))}
                      className="text-center font-mono font-semibold"
                    />
                  </div>
                ))}
              </div>

              <p className="text-xs text-gray-400 mb-4">Values must be ascending: flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban</p>

              <div className="flex items-center gap-3">
                <Button type="submit" disabled={isSubmitting}>
                  <Save className="h-3.5 w-3.5 mr-1.5" />
                  {isSubmitting ? 'Saving…' : 'Save Thresholds'}
                </Button>
                {feedback?.type === 'success' && (
                  <span className="flex items-center gap-1 text-xs text-green-600">
                    <CheckCircle className="h-3.5 w-3.5" />{feedback.message}
                  </span>
                )}
              </div>

              {feedback?.type === 'error' && (
                <Alert variant="destructive" className="mt-3">
                  <AlertCircle className="h-4 w-4" /><AlertDescription>{feedback.message}</AlertDescription>
                </Alert>
              )}
            </form>
          </div>

          {/* Score action reference */}
          <div className="mt-4 max-w-3xl bg-gray-50 rounded-lg border border-gray-200 p-4">
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-3">Score → Action reference</p>
            <div className="space-y-1.5">
              {FIELDS.map(({ key, label, color }) => (
                <div key={key} className="flex items-center justify-between text-xs">
                  <span className="text-gray-500">Score ≥ {form[key]}</span>
                  <span className={`font-medium ${color}`}>{label}</span>
                </div>
              ))}
              <div className="flex items-center justify-between text-xs border-t border-gray-200 pt-1.5 mt-1.5">
                <span className="text-gray-500">Score &lt; {form.flag}</span>
                <span className="font-medium text-green-600">Allow</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
