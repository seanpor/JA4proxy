import React, { useState } from 'react';
import { useCIDRs } from '../hooks/useApi';
import { Button, Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, Input, Label, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Plus, Trash2, Network } from 'lucide-react';
import { format } from 'date-fns';

export const CIDRsPage: React.FC = () => {
  const { data: cidrs, isLoading, error, createCIDR, deleteCIDR } = useCIDRs();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newCIDR, setNewCIDR] = useState({ cidr: '', reason: '' });

  const handleCreate = async () => {
    try {
      await createCIDR({ cidr: newCIDR.cidr, reason: newCIDR.reason });
      setIsDialogOpen(false);
      setNewCIDR({ cidr: '', reason: '' });
    } catch (err) {
      console.error('Failed to create CIDR block:', err);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-gray-900">CIDR Blocks</h1>
          <p className="text-xs text-gray-500 mt-0.5">{cidrs?.length ?? 0} network range{cidrs?.length !== 1 ? 's' : ''} blocked</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger>
            <Button size="sm"><Plus className="h-3.5 w-3.5 mr-1.5" />Add CIDR</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Add CIDR Block</DialogTitle></DialogHeader>
            <div className="space-y-3 mt-2">
              <div>
                <Label htmlFor="cidr">CIDR Notation</Label>
                <Input id="cidr" className="mt-1" value={newCIDR.cidr} onChange={e => setNewCIDR({ ...newCIDR, cidr: e.target.value })} placeholder="192.168.1.0/24" />
              </div>
              <div>
                <Label htmlFor="reason">Reason</Label>
                <Input id="reason" className="mt-1" value={newCIDR.reason} onChange={e => setNewCIDR({ ...newCIDR, reason: e.target.value })} placeholder="Known malicious network" />
              </div>
              <Button onClick={handleCreate} className="w-full mt-2">Add CIDR Block</Button>
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
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">CIDR</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Reason</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Added</th>
                  <th className="px-4 py-3 w-10"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {!cidrs || cidrs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-16 text-center text-gray-400">
                      <Network className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No CIDR blocks</p>
                    </td>
                  </tr>
                ) : cidrs.map(cidr => (
                  <tr key={cidr.cidr} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm font-medium text-gray-900">{cidr.cidr}</td>
                    <td className="px-4 py-3 text-gray-600 max-w-xs truncate">{cidr.reason || '—'}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {cidr.created_at ? format(new Date(cidr.created_at), 'dd MMM yyyy HH:mm') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => deleteCIDR(cidr.cidr)}
                        className="text-gray-400 hover:text-red-600 transition-colors p-1 rounded hover:bg-red-50"
                        title="Remove block"
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
