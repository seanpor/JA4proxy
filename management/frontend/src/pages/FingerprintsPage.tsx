import React, { useState } from 'react';
import { useFingerprints } from '../hooks/useApi';
import { Button, Card, CardHeader, CardTitle, CardContent, CardDescription, Input, Label, Alert, AlertDescription, AlertTitle, Table, TableHeader, TableRow, TableHead, TableBody, TableCell, Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, Select, SelectTrigger, SelectContent, SelectItem, Textarea, Badge, Switch, Sheet, SheetContent, SheetTrigger } from "../components/ui";
import { AlertCircle, Plus, Trash2, Fingerprint } from 'lucide-react';
import { format } from 'date-fns';

export const FingerprintsPage: React.FC = () => {
  const { data: fingerprints, isLoading, error, createFingerprint, deleteFingerprint } = useFingerprints();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [newFingerprint, setNewFingerprint] = useState({
    fingerprint: '',
    tag: '',
  });

  const handleCreateFingerprint = async () => {
    try {
      await createFingerprint({
        fingerprint: newFingerprint.fingerprint,
        tag: newFingerprint.tag,
      });
      setIsDialogOpen(false);
      setNewFingerprint({ fingerprint: '', tag: '' });
    } catch (err) {
      console.error('Failed to create fingerprint:', err);
    }
  };

  const handleDeleteFingerprint = async (fingerprint: string) => {
    try {
      await deleteFingerprint(fingerprint);
    } catch (err) {
      console.error('Failed to delete fingerprint:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Fingerprint Management</h1>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Fingerprint
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New Fingerprint</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="fingerprint">Fingerprint Hash</Label>
                <Input
                  id="fingerprint"
                  value={newFingerprint.fingerprint}
                  onChange={(e) => setNewFingerprint({ ...newFingerprint, fingerprint: e.target.value })}
                  placeholder="e.g., 771a332b45a32e3b8c4d5e6f7a8b9c0d"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tag">Tag</Label>
                <Input
                  id="tag"
                  value={newFingerprint.tag}
                  onChange={(e) => setNewFingerprint({ ...newFingerprint, tag: e.target.value })}
                  placeholder="e.g., tor_exit_node"
                />
              </div>
            </div>
            <Button onClick={handleCreateFingerprint} className="w-full">
              Create Fingerprint
            </Button>
          </DialogContent>
        </Dialog>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load fingerprints: {error.message}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>TLS Fingerprints</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">Loading fingerprints...</div>
          ) : fingerprints && fingerprints.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead>Tag</TableHead>
                  <TableHead>Created At</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {fingerprints.map((fp) => (
                  <TableRow key={fp.fingerprint}>
                    <TableCell className="font-mono font-medium max-w-[200px] truncate">
                      {fp.fingerprint}
                    </TableCell>
                    <TableCell>{fp.tag ?? '—'}</TableCell>
                    <TableCell>{fp.created_at ? format(new Date(fp.created_at), 'PPpp') : '—'}</TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDeleteFingerprint(fp.fingerprint)}
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
              <Fingerprint className="mx-auto h-8 w-8 mb-2" />
              <p>No fingerprints found</p>
              <p className="text-sm">Add TLS fingerprints to detect specific clients</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};