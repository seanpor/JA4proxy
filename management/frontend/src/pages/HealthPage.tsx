import React from 'react';
import { useHealth } from '../hooks/useApi';
import { Alert, AlertDescription } from '../components/ui';
import { AlertCircle, CheckCircle, XCircle, Clock, Database, Server, Shield } from 'lucide-react';

const StatusDot: React.FC<{ ok: boolean }> = ({ ok }) => (
  <span className={`inline-flex h-2 w-2 rounded-full ${ok ? 'bg-green-500' : 'bg-red-500'}`} />
);

export const HealthPage: React.FC = () => {
  const { data, isLoading, error } = useHealth();

  const isHealthy = data?.status === 'healthy';
  const redisOk = data?.redis !== false;

  return (
    <div className="flex flex-col h-full">
      <div className="mb-4 flex-shrink-0">
        <h1 className="text-lg font-semibold text-gray-900">System Health</h1>
        <p className="text-xs text-gray-500 mt-0.5">
          {isLoading ? 'Checking…' : isHealthy ? 'All systems operational' : 'Degraded — check components below'}
        </p>
      </div>

      {error && (
        <Alert variant="destructive" className="mb-3 flex-shrink-0">
          <AlertCircle className="h-4 w-4" /><AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}

      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl">
          {/* Overall */}
          <div className="bg-white rounded-lg border border-gray-200 p-4 md:col-span-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${isHealthy ? 'bg-green-50' : 'bg-red-50'}`}>
                  {isHealthy
                    ? <CheckCircle className="h-5 w-5 text-green-600" />
                    : <XCircle className="h-5 w-5 text-red-600" />
                  }
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">Overall Status</p>
                  <p className={`text-xs font-semibold ${isHealthy ? 'text-green-600' : 'text-red-600'}`}>
                    {isLoading ? 'Checking…' : data?.status ?? 'unknown'}
                  </p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-400">Version</p>
                <p className="text-xs font-mono text-gray-600">{data?.version ?? '—'}</p>
              </div>
            </div>
          </div>

          {/* Redis */}
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${redisOk ? 'bg-green-50' : 'bg-red-50'}`}>
                <Database className={`h-4 w-4 ${redisOk ? 'text-green-600' : 'text-red-600'}`} />
              </div>
              <div>
                <p className="text-sm font-medium text-gray-900">Redis</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <StatusDot ok={redisOk} />
                  <p className={`text-xs ${redisOk ? 'text-green-600' : 'text-red-600'}`}>
                    {redisOk ? 'Connected' : 'Disconnected'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Uptime */}
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-50">
                <Clock className="h-4 w-4 text-blue-600" />
              </div>
              <div>
                <p className="text-sm font-medium text-gray-900">Uptime</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {data?.uptime != null
                    ? `${Math.floor(data.uptime / 3600)}h ${Math.floor((data.uptime % 3600) / 60)}m`
                    : '—'}
                </p>
              </div>
            </div>
          </div>

          {/* API server */}
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-50">
                <Server className="h-4 w-4 text-green-600" />
              </div>
              <div>
                <p className="text-sm font-medium text-gray-900">Management API</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <StatusDot ok={true} />
                  <p className="text-xs text-green-600">Operational</p>
                </div>
              </div>
            </div>
          </div>

          {/* Protection engine */}
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-50">
                <Shield className="h-4 w-4 text-purple-600" />
              </div>
              <div>
                <p className="text-sm font-medium text-gray-900">Proxy Engine</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <StatusDot ok={redisOk} />
                  <p className={`text-xs ${redisOk ? 'text-green-600' : 'text-yellow-600'}`}>
                    {redisOk ? 'Active' : 'Degraded'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
