import React, { useState } from 'react';
import { useAuditLog } from '../hooks/useApi';
import { Button, Card, CardHeader, CardTitle, CardContent, CardDescription, Input, Label, Alert, AlertDescription, AlertTitle, Table, TableHeader, TableRow, TableHead, TableBody, TableCell, Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, Select, SelectTrigger, SelectContent, SelectItem, Textarea, Badge, Switch, Sheet, SheetContent, SheetTrigger } from "../components/ui";
import { AlertCircle, Search, Filter, ChevronLeft, ChevronRight, FileText } from 'lucide-react';
import { format } from 'date-fns';

export const AuditPage: React.FC = () => {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [eventTypeFilter, setEventTypeFilter] = useState('all');

  const { data, isLoading, error } = useAuditLog(page, pageSize);

  const filteredData = data?.items.filter((entry) => {
    // Filter by search term
    const matchesSearch = searchTerm === '' || 
      entry.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
      entry.event_type.toLowerCase().includes(searchTerm.toLowerCase());

    // Filter by severity
    const matchesSeverity = severityFilter === 'all' || entry.severity === severityFilter;

    // Filter by event type
    const matchesEventType = eventTypeFilter === 'all' || entry.event_type === eventTypeFilter;

    return matchesSearch && matchesSeverity && matchesEventType;
  }) || [];

  const totalPages = data ? Math.ceil(filteredData.length / pageSize) : 1;

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return <span className="px-2 py-1 bg-destructive text-destructive-foreground rounded-full text-xs">High</span>;
      case 'medium':
        return <span className="px-2 py-1 bg-yellow-500 text-yellow-900 rounded-full text-xs">Medium</span>;
      case 'low':
        return <span className="px-2 py-1 bg-blue-500 text-blue-900 rounded-full text-xs">Low</span>;
      default:
        return <span className="px-2 py-1 bg-gray-500 text-gray-900 rounded-full text-xs">Info</span>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Audit Log</h1>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>Failed to load audit log: {error.message}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Audit Log Viewer</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search audit log..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            <div className="flex gap-2">
              <Select value={severityFilter} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSeverityFilter(e.target.value)} className="w-[180px]">
                  <option value="all">All Severities</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
              </Select>

              <Select value={eventTypeFilter} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setEventTypeFilter(e.target.value)} className="w-[180px]">
                  <option value="all">All Event Types</option>
                  <option value="ban_created">Ban Created</option>
                  <option value="ban_deleted">Ban Deleted</option>
                  <option value="cidr_created">CIDR Created</option>
                  <option value="fingerprint_detected">Fingerprint Detected</option>
                  <option value="system_event">System Event</option>
              </Select>
            </div>
          </div>

          {isLoading ? (
            <div className="text-center py-8">Loading audit log...</div>
          ) : filteredData.length > 0 ? (
            <div className="space-y-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Event Type</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredData.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="font-medium">
                        {format(new Date(entry.timestamp), 'PPpp')}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs bg-muted px-2 py-1 rounded">
                          {entry.event_type}
                        </span>
                      </TableCell>
                      <TableCell>{getSeverityBadge(entry.severity)}</TableCell>
                      <TableCell className="max-w-[400px]">{entry.details}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <div className="flex items-center justify-between">
                <div className="text-sm text-muted-foreground">
                  Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, filteredData.length)} of {filteredData.length} entries
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    <span className="sr-only">Previous page</span>
                  </Button>
                  <span className="text-sm">
                    Page {page} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                  >
                    <ChevronRight className="h-4 w-4" />
                    <span className="sr-only">Next page</span>
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <FileText className="mx-auto h-8 w-8 mb-2" />
              <p>No audit log entries found</p>
              <p className="text-sm">Audit events will appear here as they occur</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit Log Statistics</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 border rounded-lg">
              <div className="text-2xl font-bold">{data?.total || 0}</div>
              <div className="text-sm text-muted-foreground">Total Events</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <div className="text-2xl font-bold">
                {data?.items.filter(e => e.severity === 'high').length || 0}
              </div>
              <div className="text-sm text-muted-foreground">High Severity</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <div className="text-2xl font-bold">
                {data?.items.filter(e => e.severity === 'medium').length || 0}
              </div>
              <div className="text-sm text-muted-foreground">Medium Severity</div>
            </div>
            <div className="text-center p-4 border rounded-lg">
              <div className="text-2xl font-bold">
                {data?.items.filter(e => e.event_type === 'ban_created').length || 0}
              </div>
              <div className="text-sm text-muted-foreground">Bans Created</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};