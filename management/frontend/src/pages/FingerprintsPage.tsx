import React, { useState } from 'react';
import { useFingerprints } from '../hooks/useApi';
import { Button, Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Plus, Trash2, Fingerprint } from 'lucide-react';
import { format } from 'date-fns';

export const FingerprintsPage: React.FC = () => {
  const { data: fingerprints, isLoading, error, createFingerprint, deleteFingerprint } = useFingerprints();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newFP, setNewFP] = useState({ fingerprint: '', tag: '' });

  const handleCreate = async () => {
    try {
      await createFingerprint({ fingerprint: newFP.fingerprint, tag: newFP.tag });
      setIsDialogOpen(false);
      setNewFP({ fingerprint: '', tag: '' });
    } catch (err) {
      console.error('Failed to create fingerprint:', err);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-gray-900">JA4 Blacklist</h1>
          <p className="text-xs text-gray-500 mt-0.5">{fingerprints?.length ?? 0} blocked fingerprint{fingerprints?.length !== 1 ? 's' : ''}</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger>
            <Button size="sm"><Plus className="h-3.5 w-3.5 mr-1.5" />Add Fingerprint</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Add to Blacklist</DialogTitle></DialogHeader>
            <div className="space-y-3 mt-2">
              <div>
                <Label htmlFor="fp">JA4 Fingerprint</Label>
                <Input id="fp" className="mt-1 font-mono text-xs" value={newFP.fingerprint} onChange={e => setNewFP({ ...newFP, fingerprint: e.target.value })} placeholder="t13d1516h2_8daaf6152771_02713d6af862" />
              </div>
              <div>
                <Label htmlFor="tag">Tag (optional)</Label>
                <Input id="tag" className="mt-1" value={newFP.tag} onChange={e => setNewFP({ ...newFP, tag: e.target.value })} placeholder="Sliver C2, CobaltStrike…" />
              </div>
              <Button onClick={handleCreate} className="w-full mt-2">Add to Blacklist</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {error && (
        <Alert variant="destructive" className="mb-3 flex-shrink-0">
          <AlertCircle className="h-4 w-4" /><AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}

      <div className="flex-1 min-h-0 rounded-lg border border-gray-200 bg-white overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading…</div>
        ) : (
          <div className="h-full overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-50 z-10">
                <tr className="border-b border-gray-200">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Fingerprint</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Tag</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Added</th>
                  <th className="px-4 py-3 w-10"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {!fingerprints || fingerprints.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-16 text-center text-gray-400">
                      <Fingerprint className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No blacklisted fingerprints</p>
                    </td>
                  </tr>
                ) : fingerprints.map(fp => (
                  <tr key={fp.fingerprint} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-gray-900">{fp.fingerprint}</td>
                    <td className="px-4 py-3">
                      {fp.tag ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-700">{fp.tag}</span>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {fp.created_at ? format(new Date(fp.created_at), 'dd MMM yyyy HH:mm') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => deleteFingerprint(fp.fingerprint)}
                        className="text-gray-400 hover:text-red-600 transition-colors p-1 rounded hover:bg-red-50"
                        title="Remove fingerprint"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
