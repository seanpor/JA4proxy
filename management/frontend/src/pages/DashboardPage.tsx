import React from 'react';
import { useSseEvents, useHealth, useBans, useCIDRs, useFingerprints, useDial } from '../hooks/useApi';
import { Shield, Users, Fingerprint, HeartPulse, Activity, Wifi, WifiOff, AlertCircle } from 'lucide-react';

const StatCard: React.FC<{ label: string; value: string | number; sub?: string; icon: React.ReactNode; color?: string }> = ({
  label, value, sub, icon, color = 'blue'
}) => {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-600',
    red: 'bg-red-50 text-red-600',
    green: 'bg-green-50 text-green-600',
    purple: 'bg-purple-50 text-purple-600',
  };
  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{label}</p>
          <p className="mt-1 text-2xl font-bold text-gray-900">{value}</p>
          {sub && <p className="mt-0.5 text-xs text-gray-400">{sub}</p>}
        </div>
        <div className={`rounded-lg p-2.5 ${colors[color] ?? colors.blue}`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

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
  const recentEvents = events.slice(0, 15);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-0.5">Live security overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Bans"
          value={activeBans}
          sub={`${bansData?.length ?? 0} total`}
          icon={<Shield className="h-5 w-5" />}
          color="red"
        />
        <StatCard
          label="CIDR Blocks"
          value={cidrsData?.length ?? 0}
          sub="network ranges"
          icon={<Users className="h-5 w-5" />}
          color="purple"
        />
        <StatCard
          label="Fingerprints"
          value={fingerprintsData?.length ?? 0}
          sub="on blacklist"
          icon={<Fingerprint className="h-5 w-5" />}
          color="blue"
        />
        <StatCard
          label="Dial"
          value={dialData?.dial ?? 0}
          sub={dialData?.dial === 0 ? 'monitor only' : 'blocking active'}
          icon={<Activity className="h-5 w-5" />}
          color={dialData?.dial === 0 ? 'green' : 'red'}
        />
      </div>

      {/* Main panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live event feed */}
        <div className="lg:col-span-2 bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-900">Live Events</h2>
            <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${isConnected ? 'text-green-600' : 'text-gray-400'}`}>
              {isConnected ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>

          <div className="divide-y divide-gray-50">
            {recentEvents.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-gray-400">
                <Activity className="h-8 w-8 mb-2 opacity-50" />
                <p className="text-sm">No events yet</p>
                <p className="text-xs mt-0.5">Events will appear here as connections arrive</p>
              </div>
            ) : (
              recentEvents.map((event, i) => (
                <div key={event.id ?? i} className="flex items-center gap-3 px-5 py-3">
                  <div className="text-xs text-gray-400 w-16 shrink-0 tabular-nums">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </div>
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${actionColor(event.type)}`}>
                    {event.type}
                  </span>
                  <span className="text-xs text-gray-600 truncate">
                    {event.data?.ip ?? event.data?.message ?? JSON.stringify(event.data).slice(0, 60)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* System status */}
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="px-5 py-4 border-b border-gray-100">
            <h2 className="text-sm font-semibold text-gray-900">System Status</h2>
          </div>
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <HeartPulse className="h-4 w-4 text-gray-400" />
                Overall
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                healthData?.status === 'healthy' ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'
              }`}>
                {healthData?.status ?? 'checking…'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <Activity className="h-4 w-4 text-gray-400" />
                Redis
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                healthData?.redis !== false ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
              }`}>
                {healthData?.redis !== false ? 'connected' : 'error'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <Shield className="h-4 w-4 text-gray-400" />
                Blocking
              </div>
              <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                dialData?.blocking_acknowledged ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'
              }`}>
                {dialData?.blocking_acknowledged ? `dial ${dialData.dial}` : 'monitor only'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <Activity className="h-4 w-4 text-gray-400" />
                Version
              </div>
              <span className="text-xs text-gray-500">{healthData?.version ?? '—'}</span>
            </div>

            {!isConnected && (
              <div className="mt-2 flex items-start gap-2 rounded-lg bg-yellow-50 border border-yellow-100 px-3 py-2 text-xs text-yellow-700">
                <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                Live feed disconnected. Events may be delayed.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
