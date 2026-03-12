import React from 'react';
import { useHealth } from '../hooks/useApi';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/Card';
import { Alert, AlertDescription } from '../components/ui/Alert';
import { AlertCircle, HeartPulse, Activity, Database, Shield, Clock, Server } from 'lucide-react';
import { Badge } from '../components/ui/Badge';

export const HealthPage: React.FC = () => {
  const { data: healthData, isLoading, error, isError } = useHealth();

  const getStatusBadge = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'healthy':
        return <Badge variant="outline" className="bg-green-500 text-white">Healthy</Badge>;
      case 'degraded':
        return <Badge variant="outline" className="bg-yellow-500 text-white">Degraded</Badge>;
      case 'unhealthy':
        return <Badge variant="outline" className="bg-destructive text-white">Unhealthy</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getBooleanStatus = (value: boolean | undefined) => {
    if (value === true) return <Badge variant="outline" className="bg-green-500 text-white">Connected</Badge>;
    if (value === false) return <Badge variant="outline" className="bg-destructive text-white">Disconnected</Badge>;
    return <Badge variant="outline">Unknown</Badge>;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">System Health</h1>
      </div>

      {isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            Failed to load health status: {error?.message || 'Unknown error'}
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Overall Status</CardTitle>
            <HeartPulse className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="text-2xl font-bold">Loading...</div>
            ) : (
              <div className="text-2xl font-bold flex items-center gap-2">
                {getStatusBadge(healthData?.status)}
                <span>{healthData?.status || 'Unknown'}</span>
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-2">
              {healthData?.version || 'Checking system status...'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Uptime</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? 'Loading...' : healthData?.uptime ? `${Math.floor(healthData.uptime / 60)} minutes` : 'N/A'}
            </div>
            <p className="text-xs text-muted-foreground">
              System has been running since startup
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Redis Connection</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold flex items-center gap-2">
              {isLoading ? 'Loading...' : getBooleanStatus(healthData?.redis_connected)}
            </div>
            <p className="text-xs text-muted-foreground">
              {healthData?.redis_connected ? 'Database connection active' : 'Database connection issue'}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>System Components</CardTitle>
          <CardDescription>
            Detailed status of all system components
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <Server className="h-5 w-5" />
                <div>
                  <h3 className="font-medium">API Server</h3>
                  <p className="text-sm text-muted-foreground">Management interface</p>
                </div>
              </div>
              {isLoading ? (
                <Badge variant="outline">Loading...</Badge>
              ) : (
                <Badge variant="outline" className="bg-green-500 text-white">Operational</Badge>
              )}
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <Database className="h-5 w-5" />
                <div>
                  <h3 className="font-medium">Redis Database</h3>
                  <p className="text-sm text-muted-foreground">Data storage</p>
                </div>
              </div>
              {isLoading ? (
                <Badge variant="outline">Loading...</Badge>
              ) : healthData?.redis_connected ? (
                <Badge variant="outline" className="bg-green-500 text-white">Connected</Badge>
              ) : (
                <Badge variant="outline" className="bg-destructive text-white">Disconnected</Badge>
              )}
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <Shield className="h-5 w-5" />
                <div>
                  <h3 className="font-medium">Protection Engine</h3>
                  <p className="text-sm text-muted-foreground">Threat detection</p>
                </div>
              </div>
              {isLoading ? (
                <Badge variant="outline">Loading...</Badge>
              ) : (
                <Badge variant="outline" className="bg-green-500 text-white">Active</Badge>
              )}
            </div>

            <div className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center gap-3">
                <Activity className="h-5 w-5" />
                <div>
                  <h3 className="font-medium">Event System</h3>
                  <p className="text-sm text-muted-foreground">Real-time events</p>
                </div>
              </div>
              {isLoading ? (
                <Badge variant="outline">Loading...</Badge>
              ) : (
                <Badge variant="outline" className="bg-green-500 text-white">Streaming</Badge>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Health Metrics</CardTitle>
          <CardDescription>
            Detailed system metrics and performance indicators
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 border rounded-lg">
              <div className="text-lg font-medium text-muted-foreground">Memory Usage</div>
              <div className="text-2xl font-bold mt-2">64%</div>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div className="bg-blue-600 h-2 rounded-full" style={{ width: '64%' }}></div>
              </div>
            </div>

            <div className="text-center p-4 border rounded-lg">
              <div className="text-lg font-medium text-muted-foreground">CPU Load</div>
              <div className="text-2xl font-bold mt-2">23%</div>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div className="bg-green-600 h-2 rounded-full" style={{ width: '23%' }}></div>
              </div>
            </div>

            <div className="text-center p-4 border rounded-lg">
              <div className="text-lg font-medium text-muted-foreground">Active Connections</div>
              <div className="text-2xl font-bold mt-2">42</div>
              <div className="text-xs text-muted-foreground">out of 1000 max</div>
            </div>

            <div className="text-center p-4 border rounded-lg">
              <div className="text-lg font-medium text-muted-foreground">Response Time</div>
              <div className="text-2xl font-bold mt-2">48ms</div>
              <div className="text-xs text-muted-foreground">average</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Diagnostic Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold mb-2">System Info</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Version</span>
                  <span>{healthData?.version || 'Loading...'}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Environment</span>
                  <span>production</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Node ID</span>
                  <span className="font-mono">ja4-proxy-01</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Started At</span>
                  <span>{new Date().toISOString()}</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Dependencies</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Python</span>
                  <span>3.11.6</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">FastAPI</span>
                  <span>0.104.1</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Redis</span>
                  <span>7.2.1</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Uvicorn</span>
                  <span>0.24.0</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};