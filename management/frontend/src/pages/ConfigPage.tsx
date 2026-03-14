import React, { useState } from 'react';
import { Badge, Alert, AlertDescription } from '../components/ui';
import {
  AlertCircle,
  CheckCircle2,
  Globe,
  Plus,
  Server,
  Trash2,
  XCircle,
} from 'lucide-react';
import { useHealth, useCountryBlocklist } from '../hooks/useApi';

const FLAG_EMOJI: Record<string, string> = {
  CN: '🇨🇳', RU: '🇷🇺', KP: '🇰🇵', IR: '🇮🇷', BY: '🇧🇾',
  SY: '🇸🇾', CU: '🇨🇺', VE: '🇻🇪', MM: '🇲🇲', AF: '🇦🇫',
  US: '🇺🇸', GB: '🇬🇧', DE: '🇩🇪', FR: '🇫🇷', JP: '🇯🇵',
};

const flag = (cc: string) => FLAG_EMOJI[cc] ?? '🏳';

export const ConfigPage: React.FC = () => {
  const { data: health, isLoading: healthLoading } = useHealth();
  const {
    data: countries,
    isLoading: countriesLoading,
    error: countriesError,
    addCountry,
    removeCountry,
    isAdding,
  } = useCountryBlocklist();

  const [newCountry, setNewCountry] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const handleAdd = async () => {
    const cc = newCountry.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) {
      setAddError('Enter a 2-letter ISO country code (e.g. CN, RU)');
      return;
    }
    if (countries?.includes(cc)) {
      setAddError(`${cc} is already blocked`);
      return;
    }
    try {
      setAddError(null);
      await addCountry(cc);
      setNewCountry('');
    } catch {
      setAddError('Failed to add country — check backend connection');
    }
  };

  const handleRemove = async (cc: string) => {
    try {
      setRemoveError(null);
      await removeCountry(cc);
    } catch {
      setRemoveError(`Failed to remove ${cc}`);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleAdd();
  };

  // derive component status indicators
  const redisOk =
    health?.redis === true || health?.components?.redis === 'healthy';
  const overallOk = health?.status === 'healthy';

  return (
    <div className="flex flex-col h-full">
      {/* ── Header ────────────────────────────────────────────────── */}
      <div className="flex-shrink-0 flex items-center justify-between px-6 py-4 border-b bg-background">
        <div>
          <h1 className="text-lg font-semibold">System</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Runtime status · Country geo-blocking
          </p>
        </div>
        {!healthLoading && (
          <div className="flex items-center gap-1.5">
            {overallOk ? (
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            ) : (
              <XCircle className="h-4 w-4 text-red-500" />
            )}
            <span className={`text-sm font-medium ${overallOk ? 'text-green-600' : 'text-red-600'}`}>
              {overallOk ? 'Operational' : 'Degraded'}
            </span>
          </div>
        )}
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-6 py-4 space-y-4">

        {/* ── System status ─────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            {
              label: 'Proxy Engine',
              ok: overallOk,
              detail: healthLoading ? '…' : (overallOk ? 'Running' : 'Error'),
              icon: <Server className="h-4 w-4" />,
            },
            {
              label: 'Redis',
              ok: redisOk,
              detail: healthLoading ? '…' : (redisOk ? 'Connected' : 'Error'),
              icon: <Server className="h-4 w-4" />,
            },
            {
              label: 'Version',
              ok: true,
              detail: health?.version ?? '—',
              icon: <Server className="h-4 w-4" />,
            },
            {
              label: 'Uptime',
              ok: true,
              detail: health?.uptime != null
                ? `${Math.floor(health.uptime / 3600)}h ${Math.floor((health.uptime % 3600) / 60)}m`
                : '—',
              icon: <Server className="h-4 w-4" />,
            },
          ].map(({ label, ok, detail }) => (
            <div
              key={label}
              className="rounded-lg border bg-card px-4 py-3 flex flex-col gap-1"
            >
              <span className="text-xs text-muted-foreground">{label}</span>
              <div className="flex items-center gap-1.5">
                <span
                  className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${
                    ok ? 'bg-green-500' : 'bg-red-500'
                  }`}
                />
                <span className="text-sm font-semibold truncate">{detail}</span>
              </div>
            </div>
          ))}
        </div>

        {/* ── Country blocklist ──────────────────────────────────── */}
        <div className="rounded-lg border bg-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/30">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-semibold">Country Geo-Block</span>
              {!countriesLoading && (
                <Badge variant="outline" className="text-xs">
                  {countries?.length ?? 0} blocked
                </Badge>
              )}
            </div>

            {/* Add country input */}
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newCountry}
                onChange={e => setNewCountry(e.target.value.toUpperCase().slice(0, 2))}
                onKeyDown={handleKey}
                placeholder="CC"
                maxLength={2}
                className="w-14 rounded border border-input bg-background px-2 py-1 text-sm font-mono text-center uppercase focus:outline-none focus:ring-1 focus:ring-ring"
              />
              <button
                onClick={handleAdd}
                disabled={isAdding || !newCountry}
                className="inline-flex items-center gap-1 rounded border border-input bg-background px-3 py-1 text-sm hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                {isAdding ? 'Adding…' : 'Block country'}
              </button>
            </div>
          </div>

          {addError && (
            <div className="px-4 py-2 bg-red-50 border-b border-red-100">
              <Alert variant="destructive" className="py-1 border-0 bg-transparent">
                <AlertCircle className="h-3.5 w-3.5" />
                <AlertDescription className="text-xs">{addError}</AlertDescription>
              </Alert>
            </div>
          )}

          {removeError && (
            <div className="px-4 py-2 bg-red-50 border-b border-red-100">
              <Alert variant="destructive" className="py-1 border-0 bg-transparent">
                <AlertCircle className="h-3.5 w-3.5" />
                <AlertDescription className="text-xs">{removeError}</AlertDescription>
              </Alert>
            </div>
          )}

          {countriesLoading ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              Loading…
            </div>
          ) : countriesError ? (
            <div className="px-4 py-8 text-center text-sm text-red-500">
              Failed to load country blocklist
            </div>
          ) : !countries || countries.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <Globe className="h-8 w-8 text-muted-foreground/40 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No countries blocked</p>
              <p className="text-xs text-muted-foreground mt-1">
                Enter a 2-letter ISO code above to add one
              </p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-muted/20 text-xs text-muted-foreground">
                <tr>
                  <th className="text-left px-4 py-2 font-medium">Country</th>
                  <th className="text-left px-4 py-2 font-medium">Code</th>
                  <th className="text-left px-4 py-2 font-medium">Effect</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[...countries].sort().map(cc => (
                  <tr key={cc} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 font-mono">
                      <span className="mr-2 text-base">{flag(cc)}</span>
                      {cc}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">
                      ISO 3166-1 alpha-2
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant="destructive" className="text-xs">
                        Hard block
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => handleRemove(cc)}
                        className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:text-red-600 hover:bg-red-50 transition-colors"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* ── Info note ─────────────────────────────────────────── */}
        <p className="text-xs text-muted-foreground pb-2">
          Country blocks use GeoIP lookup and are applied before the scoring
          pipeline — connections are RST'd immediately. Changes take effect on
          the next connection; no proxy restart required.
        </p>
      </div>
    </div>
  );
};
