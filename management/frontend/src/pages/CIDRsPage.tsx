import React, { useState } from 'react';
import { useCIDRs } from '../hooks/useApi';
import { Button } from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '../components/ui/Table';
import { Input } from '../components/ui/Input';
import { Label } from '../components/ui/Label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '../components/ui/Dialog';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, Plus, Trash2, Network } from 'lucide-react';
import { format } from 'date-fns';

export const CIDRsPage: React.FC = () => {
  const { data: cidrs, isLoading, error, createCIDR, deleteCIDR } = useCIDRs();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newCIDR, setNewCIDR] = useState({
    cidr: '',
    reason: '',
  });

  const handleCreateCIDR = async () => {
    try {
      await createCIDR({
        cidr: newCIDR.cidr,
        reason: newCIDR.reason,
      });
      setIsDialogOpen(false);
      setNewCIDR({ cidr: '', reason: '' });
    } catch (err) {
      console.error('Failed to create CIDR:', err);
    }
  };

  const handleDeleteCIDR = async (id: string) => {
    try {
      await deleteCIDR(id);
    } catch (err) {
      console.error('Failed to delete CIDR:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">CIDR Management</h1>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add CIDR
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New CIDR Block</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="cidr">CIDR Notation</Label>
                <Input
                  id="cidr"
                  value={newCIDR.cidr}
                  onChange={(e) => setNewCIDR({ ...newCIDR, cidr: e.target.value })}
                  placeholder="e.g., 192.168.1.0/24"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="reason">Reason</Label>
                <Input
                  id="reason"
                  value={newCIDR.reason}
                  onChange={(e) => setNewCIDR({ ...newCIDR, reason: e.target.value })}
                  placeholder="e.g., Known malicious network"
                />
              </div>
            </div>
            <Button onClick={handleCreateCIDR} className="w-full">
              Create CIDR Block
            </Button>
          </DialogContent>
        </Dialog>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load CIDR blocks: {error.message}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>CIDR Blocks</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading CIDR blocks...</div>
          ) : cidrs && cidrs.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CIDR</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Created At</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cidrs.map((cidr) => (
                  <TableRow key={cidr.id}>
                    <TableCell className="font-medium">{cidr.cidr}</TableCell>
                    <TableCell>{cidr.reason}</TableCell>
                    <TableCell>{format(new Date(cidr.created_at), 'PPpp')}</TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDeleteCIDR(cidr.id)}
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
              <Network className="mx-auto h-8 w-8 mb-2" />
              <p>No CIDR blocks found</p>
              <p className="text-sm">Add CIDR blocks to protect network ranges</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};