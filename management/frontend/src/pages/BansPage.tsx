import React, { useState } from 'react';
import { useBans } from '../hooks/useApi';
import { Button, Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Plus, Trash2, Shield } from 'lucide-react';
import { format } from 'date-fns';

export const BansPage: React.FC = () => {
  const { data: bans, isLoading, error, createBan, deleteBan } = useBans();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newBan, setNewBan] = useState({ ip: '', reason: '', expires_at: '' });

  const handleCreateBan = async () => {
    try {
      await createBan({ ip: newBan.ip, reason: newBan.reason, expires_at: newBan.expires_at });
      setIsDialogOpen(false);
      setNewBan({ ip: '', reason: '', expires_at: '' });
    } catch (err) {
      console.error('Failed to create ban:', err);
    }
  };

  const isExpired = (expiresAt: string) => new Date(expiresAt) < new Date();

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-gray-900">Bans</h1>
          <p className="text-xs text-gray-500 mt-0.5">{bans?.length ?? 0} active ban{bans?.length !== 1 ? 's' : ''}</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger>
            <Button size="sm"><Plus className="h-3.5 w-3.5 mr-1.5" />Add Ban</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Add Ban</DialogTitle></DialogHeader>
            <div className="space-y-3 mt-2">
              <div>
                <Label htmlFor="ip">IP Address</Label>
                <Input id="ip" className="mt-1" value={newBan.ip} onChange={e => setNewBan({ ...newBan, ip: e.target.value })} placeholder="192.168.1.100" />
              </div>
              <div>
                <Label htmlFor="reason">Reason</Label>
                <Input id="reason" className="mt-1" value={newBan.reason} onChange={e => setNewBan({ ...newBan, reason: e.target.value })} placeholder="Malicious activity" />
              </div>
              <div>
                <Label htmlFor="expires">Expires (optional)</Label>
                <Input id="expires" type="datetime-local" className="mt-1" value={newBan.expires_at} onChange={e => setNewBan({ ...newBan, expires_at: e.target.value })} />
              </div>
              <Button onClick={handleCreateBan} className="w-full mt-2">Add Ban</Button>
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
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Reason</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Expires</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 w-10"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {!bans || bans.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-16 text-center text-gray-400">
                      <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No bans yet</p>
                    </td>
                  </tr>
                ) : bans.map(ban => (
                  <tr key={ban.ip} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm font-medium text-gray-900">{ban.ip}</td>
                    <td className="px-4 py-3 text-gray-600 max-w-xs truncate">{ban.reason || '—'}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {ban.expires_at ? format(new Date(ban.expires_at), 'dd MMM yyyy HH:mm') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {ban.expires_at && isExpired(ban.expires_at) ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500">Expired</span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-700">Active</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => deleteBan(ban.ip)}
                        className="text-gray-400 hover:text-red-600 transition-colors p-1 rounded hover:bg-red-50"
                        title="Remove ban"
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
