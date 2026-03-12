import React, { useState } from 'react';
import { useBans } from '../hooks/useApi';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../components/ui/Table';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/Dialog';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, Plus, Trash2, Shield } from 'lucide-react';
import { format } from 'date-fns';

export const BansPage: React.FC = () => {
  const { data: bans, isLoading, error, createBan, deleteBan } = useBans();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newBan, setNewBan] = useState({
    ip: '',
    reason: '',
    expires_at: '',
  });

  const handleCreateBan = async () => {
    try {
      await createBan({
        ip: newBan.ip,
        reason: newBan.reason,
        expires_at: newBan.expires_at,
      });
      setIsDialogOpen(false);
      setNewBan({ ip: '', reason: '', expires_at: '' });
    } catch (err) {
      console.error('Failed to create ban:', err);
    }
  };

  const handleDeleteBan = async (id: string) => {
    try {
      await deleteBan(id);
    } catch (err) {
      console.error('Failed to delete ban:', err);
    }
  };

  const isBanExpired = (expiresAt: string) => {
    return new Date(expiresAt) < new Date();
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Ban Management</h1>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Ban
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New Ban</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="ip">IP Address</Label>
                <Input
                  id="ip"
                  value={newBan.ip}
                  onChange={(e) => setNewBan({ ...newBan, ip: e.target.value })}
                  placeholder="e.g., 192.168.1.100"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="reason">Reason</Label>
                <Input
                  id="reason"
                  value={newBan.reason}
                  onChange={(e) => setNewBan({ ...newBan, reason: e.target.value })}
                  placeholder="e.g., Malicious activity detected"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="expires_at">Expiration Date</Label>
                <Input
                  id="expires_at"
                  type="datetime-local"
                  value={newBan.expires_at}
                  onChange={(e) => setNewBan({ ...newBan, expires_at: e.target.value })}
                />
              </div>
            </div>
            <Button onClick={handleCreateBan} className="w-full">
              Create Ban
            </Button>
          </DialogContent>
        </Dialog>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load bans: {error.message}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Active Bans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading bans...</div>
          ) : bans && bans.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Expires At</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bans.map((ban) => (
                  <TableRow key={ban.id}>
                    <TableCell className="font-medium">{ban.ip}</TableCell>
                    <TableCell>{ban.reason}</TableCell>
                    <TableCell>{format(new Date(ban.expires_at), 'PPpp')}</TableCell>
                    <TableCell>
                      {isBanExpired(ban.expires_at) ? (
                        <span className="text-muted-foreground">Expired</span>
                      ) : (
                        <span className="text-green-600">Active</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDeleteBan(ban.id)}
                        disabled={isBanExpired(ban.expires_at)}
                      >
                        <Trash2 className="h-4 w-4" />
                        <span className="sr-only">Delete</span>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="mx-auto h-8 w-8 mb-2" />
              <p>No active bans found</p>
              <p className="text-sm">Add a ban to protect your system</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};