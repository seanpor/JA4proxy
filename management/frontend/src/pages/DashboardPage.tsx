import React from 'react';
import { useSseEvents, useHealth, useBans, useCIDRs, useFingerprints } from '../hooks/useApi';
import { Card, CardHeader, CardTitle, CardContent, Badge, Table, TableHeader, TableRow, TableHead, TableBody, TableCell, Alert, AlertTitle, AlertDescription } from '../components/ui';
import { AlertCircle, Shield, Users, Fingerprint, HeartPulse, Activity } from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const { events, isConnected } = useSseEvents();
  const { data: healthData, isLoading: isHealthLoading } = useHealth();
  const { data: bansData } = useBans();
  const { data: cidrsData } = useCIDRs();
  const { data: fingerprintsData } = useFingerprints();

  // Calculate statistics
  const activeBans = bansData?.filter(ban => new Date(ban.expires_at) > new Date()).length || 0;
  const totalCidrs = cidrsData?.length || 0;
  const totalFingerprints = fingerprintsData?.length || 0;

  // Get recent events (last 10)
  const recentEvents = events.slice(0, 10);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Bans</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{activeBans}</div>
            <p className="text-xs text-muted-foreground">
              {bansData?.length || 0} total bans
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">CIDR Blocks</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalCidrs}</div>
            <p className="text-xs text-muted-foreground">
              Network ranges blocked
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Fingerprints</CardTitle>
            <Fingerprint className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalFingerprints}</div>
            <p className="text-xs text-muted-foreground">
              TLS fingerprint patterns
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Health</CardTitle>
            <HeartPulse className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isHealthLoading ? 'Loading...' : healthData?.status || 'Unknown'}
            </div>
            <p className="text-xs text-muted-foreground">
              {healthData?.version || 'Checking...'}
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Recent Events</CardTitle>
          </CardHeader>
          <CardContent>
            {!isConnected && (
              <Alert variant="destructive" className="mb-4">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Connection Issue</AlertTitle>
                <AlertDescription>
                  Not connected to real-time events. Some features may be limited.
                </AlertDescription>
              </Alert>
            )}

            {recentEvents.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No recent events
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentEvents.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell className="font-medium">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{event.type}</Badge>
                      </TableCell>
                      <TableCell>{event.data?.message || 'N/A'}</TableCell>
                      <TableCell>
                        <Badge variant={event.data?.severity === 'high' ? 'destructive' : 'outline'}>
                          {event.data?.severity || 'info'}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                <span>Uptime</span>
              </div>
              <span>{healthData?.uptime ? `${Math.floor(healthData.uptime / 60)} minutes` : 'Loading...'}</span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <HeartPulse className="h-4 w-4" />
                <span>Redis Connection</span>
              </div>
              <Badge variant={healthData?.redis_connected ? 'outline' : 'destructive'}>
                {healthData?.redis_connected ? 'Connected' : 'Disconnected'}
              </Badge>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span>Protection Status</span>
              </div>
              <Badge variant="outline">Active</Badge>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};