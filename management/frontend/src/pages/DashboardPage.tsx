import React from 'react';
import { useSseEvents, useHealth, useBans, useCIDRs, useFingerprints, useDial } from '../hooks/useApi';
import { Shield, Users, Fingerprint, HeartPulse, Activity, Wifi, WifiOff, AlertCircle } from 'lucide-react';

const actionColor = (action: string) => {
  if (action === 'block' || action === 'ban') return 'bg-red-100 text-red-700';
  if (action === 'tarpit') return 'bg-orange-100 text-orange-700';
  if (action === 'flag' || action === 'rate_limit') return 'bg-yellow-100 text-yellow-700';
  return 'bg-green-100 text-green-700';
};

export const DashboardPage: React.FC = () => {
  const { events, isConnected } = useSseEvents();
  const { data: healthData } = useHealth();
  const { data: bansData } = useBans();
  const { data: cidrsData } = useCIDRs();
  const { data: fingerprintsData } = useFingerprints();
  const { data: dialData } = useDial();

  const activeBans = bansData?.filter(b => !b.expires_at || new Date(b.expires_at) > new Date()).length ?? 0;

  return (
    <div className="flex flex-col h-full">
      <div className="mb-4 flex-shrink-0">
        <h1 className="text-lg font-semibold text-gray-900">Dashboard</h1>
        <p className="text-xs text-gray-500 mt-0.5">Live security overview</p>
      </div>

      {/* Stat strip */}
      <div className="grid grid-cols-4 gap-3 mb-4 flex-shrink-0">
        {[
          { label: 'Active Bans', value: activeBans, icon: <Shield className="h-4 w-4" />, color: 'red' },
          { label: 'CIDR Blocks', value: cidrsData?.length ?? 0, icon: <Users className="h-4 w-4" />, color: 'purple' },
          { label: 'JA4 Blacklist', value: fingerprintsData?.length ?? 0, icon: <Fingerprint className="h-4 w-4" />, color: 'blue' },
          { label: 'Dial', value: dialData?.dial ?? 0, icon: <Activity className="h-4 w-4" />, color: dialData?.dial === 0 ? 'green' : 'orange' },
        ].map(({ label, value, icon, color }) => {
          const colors: Record<string, string> = {
            red: 'text-red-600 bg-red-50', purple: 'text-purple-600 bg-purple-50',
            blue: 'text-blue-600 bg-blue-50', green: 'text-green-600 bg-green-50',
            orange: 'text-orange-600 bg-orange-50',
          };
          return (
            <div key={label} className="bg-white rounded-lg border border-gray-200 px-4 py-3 flex items-center gap-3">
              <div className={`rounded-lg p-2 ${colors[color]}`}>{icon}</div>
              <div>
                <p className="text-xs text-gray-500">{label}</p>
                <p className="text-xl font-bold text-gray-900 leading-tight">{value}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main panels — fill remaining height */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Live feed */}
        <div className="lg:col-span-2 bg-white rounded-lg border border-gray-200 flex flex-col min-h-0">
          <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between flex-shrink-0">
            <span className="text-sm font-semibold text-gray-900">Live Events</span>
            <span className={`flex items-center gap-1.5 text-xs font-medium ${isConnected ? 'text-green-600' : 'text-gray-400'}`}>
              {isConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
              {isConnected ? 'Live' : 'Offline'}
            </span>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto">
            {events.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-400 py-8">
                <Activity className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-sm">No events yet</p>
                <p className="text-xs mt-0.5">Events appear here as connections arrive</p>
              </div>
            ) : (
              <div className="divide-y divide-gray-50">
                {events.slice(0, 50).map((event, i) => (
                  <div key={event.id ?? i} className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50">
                    <span className="text-xs text-gray-400 w-16 shrink-0 tabular-nums">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium shrink-0 ${actionColor(event.type)}`}>
                      {event.type}
                    </span>
                    <span className="text-xs text-gray-600 truncate">
                      {event.data?.ip ?? event.data?.message ?? JSON.stringify(event.data).slice(0, 60)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Status panel */}
        <div className="bg-white rounded-lg border border-gray-200 flex flex-col min-h-0">
          <div className="px-4 py-3 border-b border-gray-100 flex-shrink-0">
            <span className="text-sm font-semibold text-gray-900">System Status</span>
          </div>
          <div className="flex-1 p-4 space-y-3">
            {[
              {
                label: 'Overall',
                icon: <HeartPulse className="h-3.5 w-3.5 text-gray-400" />,
                value: healthData?.status ?? 'checking…',
                ok: healthData?.status === 'healthy',
              },
              {
                label: 'Redis',
                icon: <Activity className="h-3.5 w-3.5 text-gray-400" />,
                value: healthData?.redis !== false ? 'connected' : 'error',
                ok: healthData?.redis !== false,
              },
              {
                label: 'Blocking',
                icon: <Shield className="h-3.5 w-3.5 text-gray-400" />,
                value: dialData?.blocking_acknowledged ? `dial ${dialData.dial}` : 'monitor only',
                ok: true,
              },
              {
                label: 'Version',
                icon: <Activity className="h-3.5 w-3.5 text-gray-400" />,
                value: healthData?.version ?? '—',
                ok: true,
              },
            ].map(({ label, icon, value, ok }) => (
              <div key={label} className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  {icon}{label}
                </div>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${ok ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                  {value}
                </span>
              </div>
            ))}

            {!isConnected && (
              <div className="flex items-start gap-2 rounded-lg bg-yellow-50 border border-yellow-100 px-3 py-2">
                <AlertCircle className="h-3.5 w-3.5 text-yellow-600 mt-0.5 shrink-0" />
                <p className="text-xs text-yellow-700">Live feed disconnected</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
