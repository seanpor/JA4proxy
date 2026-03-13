import React, { useState } from 'react';
import { useAuditLog } from '../hooks/useApi';
import { Input, Alert, AlertDescription } from '../components/ui';
import { AlertCircle, Search, FileText } from 'lucide-react';
import { format } from 'date-fns';

const severityClass = (s: string) => {
  if (s === 'high') return 'bg-red-100 text-red-700';
  if (s === 'medium') return 'bg-yellow-100 text-yellow-700';
  if (s === 'low') return 'bg-blue-100 text-blue-700';
  return 'bg-gray-100 text-gray-600';
};

export const AuditPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const { data, isLoading, error } = useAuditLog(1, 200);

  const filtered = (data?.items ?? []).filter(e => {
    const matchSearch = !searchTerm ||
      e.details?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.event_type?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchSeverity = severityFilter === 'all' || e.severity === severityFilter;
    return matchSearch && matchSeverity;
  });

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-gray-900">Audit Log</h1>
          <p className="text-xs text-gray-500 mt-0.5">{data?.total ?? 0} total events</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-3 flex-shrink-0">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <Input
            className="pl-8 h-8 text-xs"
            placeholder="Search events…"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSeverityFilter(e.target.value)}
          className="h-8 rounded-md border border-gray-300 bg-white px-3 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="all">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {error && (
        <Alert variant="destructive" className="mb-3 flex-shrink-0">
          <AlertCircle className="h-4 w-4" /><AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}

      <div className="flex-1 min-h-0 rounded-lg border border-gray-200 bg-white overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-gray-400 text-sm">Loading…</div>
        ) : (
          <div className="h-full overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-gray-50 z-10">
                <tr className="border-b border-gray-200">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-40">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-32">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-40">Event</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-16 text-center text-gray-400">
                      <FileText className="h-8 w-8 mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No events found</p>
                    </td>
                  </tr>
                ) : filtered.map((entry, i) => (
                  <tr key={entry.id ?? i} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 text-xs text-gray-500 tabular-nums whitespace-nowrap">
                      {format(new Date(entry.timestamp), 'dd MMM HH:mm:ss')}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${severityClass(entry.severity)}`}>
                        {entry.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-700">{entry.event_type}</td>
                    <td className="px-4 py-3 text-xs text-gray-600 max-w-md truncate">{entry.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
