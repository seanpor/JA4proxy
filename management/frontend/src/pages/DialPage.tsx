import React, { useState } from 'react';
import { useDial } from '../hooks/useApi';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Textarea } from '../components/ui/Textarea';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, Phone, Copy, Check } from 'lucide-react';
import { useToast } from '../hooks/useToast';

export const DialPage: React.FC = () => {
  const { mutate: dial, isPending, error, data: result } = useDial();
  const [fingerprint, setFingerprint] = useState('');
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleDial = () => {
    if (!fingerprint.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter a fingerprint',
        variant: 'destructive',
      });
      return;
    }
    dial(fingerprint);
  };

  const handleCopyResult = () => {
    if (result) {
      navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({
        title: 'Copied',
        description: 'Result copied to clipboard',
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Counterfactual Testing</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Test Fingerprint</CardTitle>
          <CardDescription>
            Enter a TLS fingerprint to test against the current policy rules
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="fingerprint">TLS Fingerprint</Label>
            <Input
              id="fingerprint"
              value={fingerprint}
              onChange={(e) => setFingerprint(e.target.value)}
              placeholder="e.g., 771a332b45a32e3b8c4d5e6f7a8b9c0d"
              className="font-mono"
            />
          </div>

          <Button onClick={handleDial} disabled={isPending} className="w-full sm:w-auto">
            <Phone className="h-4 w-4 mr-2" />
            {isPending ? 'Testing...' : 'Test Fingerprint'}
          </Button>

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                Failed to test fingerprint: {error.message}
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Test Result</CardTitle>
            <CardDescription>
              Counterfactual analysis of the fingerprint against current rules
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-end">
              <Button variant="outline" size="sm" onClick={handleCopyResult}>
                {copied ? (
                  <Check className="h-4 w-4 mr-2" />
                ) : (
                  <Copy className="h-4 w-4 mr-2" />
                )}
                {copied ? 'Copied!' : 'Copy Result'}
              </Button>
            </div>

            <div className="space-y-4">
              <div>
                <h3 className="font-semibold mb-2">Decision</h3>
                <div className="p-4 border rounded-lg bg-muted">
                  <p className="font-mono text-lg">
                    {result.decision || 'No decision data'}
                  </p>
                </div>
              </div>

              <div>
                <h3 className="font-semibold mb-2">Rules Matched</h3>
                <div className="p-4 border rounded-lg bg-muted">
                  {result.rules_matched && result.rules_matched.length > 0 ? (
                    <ul className="list-disc list-inside space-y-1">
                      {result.rules_matched.map((rule: any, index: number) => (
                        <li key={index} className="font-mono text-sm">
                          {rule.name || rule.id || `Rule ${index + 1}`}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-muted-foreground">No rules matched</p>
                  )}
                </div>
              </div>

              <div>
                <h3 className="font-semibold mb-2">Additional Data</h3>
                <div className="p-4 border rounded-lg bg-muted">
                  <Textarea
                    value={JSON.stringify(result.additional_data || {}, null, 2)}
                    readOnly
                    className="font-mono text-sm h-40"
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};