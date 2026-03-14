import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';

// Types for API responses
interface Ban {
  ip: string;
  reason: string;
  expires_at: string;
  created_at: string;
}

interface CIDR {
  cidr: string;
  reason: string;
  created_at: string;
}

interface Fingerprint {
  fingerprint: string;
  tag?: string;
  created_at?: string;
}

interface ThresholdConfig {
  flag: number;
  rate_limit: number;
  tarpit: number;
  block: number;
  ban: number;
}

interface AuditLogEntry {
  id: string;
  timestamp: string;
  event_type: string;
  details: string;
  severity: string;
}

interface HealthStatus {
  status: string;
  version?: string;
  uptime?: number;
  redis?: boolean | string;
  redis_connected?: boolean;
  components?: Record<string, string>;
}

interface Event {
  id: string;
  type: string;
  data: any;
  timestamp: string;
}

// Ban hooks
export const useBans = () => {
  const queryClient = useQueryClient();

  const getBans = async (): Promise<Ban[]> => {
    const response = await apiClient.get('/bans');
    // API returns paginated { items: [...], total, page, per_page }
    return response.data.items ?? response.data;
  };

  const createBan = async (banData: Omit<Ban, 'created_at'>): Promise<Ban> => {
    const response = await apiClient.post('/bans', banData);
    return response.data;
  };

  const deleteBan = async (ip: string): Promise<void> => {
    await apiClient.delete(`/bans/${ip}`);
  };

  const bansQuery = useQuery<Ban[], Error>({
    queryKey: ['bans'],
    queryFn: getBans,
  });

  const createBanMutation = useMutation<Ban, Error, Omit<Ban, 'created_at'>>({
    mutationFn: createBan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bans'] });
    },
  });

  const deleteBanMutation = useMutation<void, Error, string>({
    mutationFn: deleteBan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bans'] });
    },
  });

  return {
    ...bansQuery,
    createBan: createBanMutation.mutateAsync,
    deleteBan: deleteBanMutation.mutateAsync,
  };
};

// CIDR hooks
export const useCIDRs = () => {
  const queryClient = useQueryClient();

  const getCIDRs = async (): Promise<CIDR[]> => {
    const response = await apiClient.get('/cidrs');
    return response.data.items ?? response.data;
  };

  const createCIDR = async (cidrData: Omit<CIDR, 'created_at'>): Promise<CIDR> => {
    const response = await apiClient.post('/cidrs', cidrData);
    return response.data;
  };

  const deleteCIDR = async (cidr: string): Promise<void> => {
    await apiClient.delete(`/cidrs/${encodeURIComponent(cidr)}`);
  };

  const cidrsQuery = useQuery<CIDR[], Error>({
    queryKey: ['cidrs'],
    queryFn: getCIDRs,
  });

  const createCIDRMutation = useMutation<CIDR, Error, Omit<CIDR, 'created_at'>>({
    mutationFn: createCIDR,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cidrs'] });
    },
  });

  const deleteCIDRMutation = useMutation<void, Error, string>({
    mutationFn: deleteCIDR,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cidrs'] });
    },
  });

  return {
    ...cidrsQuery,
    createCIDR: createCIDRMutation.mutateAsync,
    deleteCIDR: deleteCIDRMutation.mutateAsync,
  };
};

// Fingerprint hooks
export const useFingerprints = () => {
  const queryClient = useQueryClient();

  const getFingerprints = async (): Promise<Fingerprint[]> => {
    const response = await apiClient.get('/fingerprints/blacklist');
    return response.data.items ?? response.data;
  };

  const createFingerprint = async (fp: { fingerprint: string; tag?: string }): Promise<Fingerprint> => {
    const response = await apiClient.post('/fingerprints/blacklist', fp);
    return response.data;
  };

  const deleteFingerprint = async (fingerprint: string): Promise<void> => {
    await apiClient.delete(`/fingerprints/blacklist/${encodeURIComponent(fingerprint)}`);
  };

  const fingerprintsQuery = useQuery<Fingerprint[], Error>({
    queryKey: ['fingerprints'],
    queryFn: getFingerprints,
  });

  const createFingerprintMutation = useMutation<Fingerprint, Error, { fingerprint: string; tag?: string }>({
    mutationFn: createFingerprint,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] });
    },
  });

  const deleteFingerprintMutation = useMutation<void, Error, string>({
    mutationFn: deleteFingerprint,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fingerprints'] });
    },
  });

  return {
    ...fingerprintsQuery,
    createFingerprint: createFingerprintMutation.mutateAsync,
    deleteFingerprint: deleteFingerprintMutation.mutateAsync,
  };
};

// Threshold config hooks
export const useThresholdConfig = () => {
  const queryClient = useQueryClient();

  const getThresholdConfig = async (): Promise<ThresholdConfig> => {
    const response = await apiClient.get('/config/thresholds');
    return response.data;
  };

  const updateThresholdConfig = async (config: ThresholdConfig): Promise<ThresholdConfig> => {
    const response = await apiClient.put('/config/thresholds', config);
    return response.data;
  };

  const thresholdConfigQuery = useQuery<ThresholdConfig, Error>({
    queryKey: ['thresholdConfig'],
    queryFn: getThresholdConfig,
  });

  const updateThresholdConfigMutation = useMutation<ThresholdConfig, Error, ThresholdConfig>({
    mutationFn: updateThresholdConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['thresholdConfig'] });
    },
  });

  return {
    ...thresholdConfigQuery,
    updateThresholdConfig: updateThresholdConfigMutation.mutateAsync,
  };
};

// Audit log hooks
export const useAuditLog = (page: number = 1, pageSize: number = 50) => {
  const getAuditLog = async (): Promise<{ items: AuditLogEntry[]; total: number }> => {
    const response = await apiClient.get('/audit', {
      params: { page, page_size: pageSize }
    });
    return response.data;
  };

  return useQuery<{ items: AuditLogEntry[]; total: number }, Error>({
    queryKey: ['auditLog', page, pageSize],
    queryFn: getAuditLog,
  });
};

// Health hooks — /health is mounted without /api/v1 prefix
export const useHealth = () => {
  const getHealth = async (): Promise<HealthStatus> => {
    const response = await apiClient.get('/health/detail');
    return response.data;
  };

  return useQuery<HealthStatus, Error>({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 30000, // Refetch every 30 seconds
  });
};

// Dial hooks
export const useDial = () => {
  const queryClient = useQueryClient();

  const getDial = async (): Promise<{ dial: number; blocking_acknowledged: boolean }> => {
    const response = await apiClient.get('/dial');
    return response.data;
  };

  const setDial = async (value: number): Promise<any> => {
    const response = await apiClient.post('/dial', { value });
    return response.data;
  };

  const dialQuery = useQuery({
    queryKey: ['dial'],
    queryFn: getDial,
  });

  const setDialMutation = useMutation<any, Error, number>({
    mutationFn: setDial,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dial'] });
    },
  });

  return {
    ...dialQuery,
    setDial: setDialMutation.mutateAsync,
  };
};

// Country blocklist hooks
export const useCountryBlocklist = () => {
  const queryClient = useQueryClient();

  const getCountries = async (): Promise<string[]> => {
    const response = await apiClient.get('/config/countries/blocklist');
    return response.data.countries ?? [];
  };

  const addCountry = async (country: string): Promise<void> => {
    const current = await getCountries();
    const updated = Array.from(new Set([...current, country.toUpperCase()]));
    await apiClient.put('/config/countries/blocklist', { countries: updated });
  };

  const removeCountry = async (country: string): Promise<void> => {
    const current = await getCountries();
    const updated = current.filter(c => c !== country);
    await apiClient.put('/config/countries/blocklist', { countries: updated });
  };

  const countriesQuery = useQuery<string[], Error>({
    queryKey: ['countryBlocklist'],
    queryFn: getCountries,
  });

  const addMutation = useMutation<void, Error, string>({
    mutationFn: addCountry,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['countryBlocklist'] }),
  });

  const removeMutation = useMutation<void, Error, string>({
    mutationFn: removeCountry,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['countryBlocklist'] }),
  });

  return {
    ...countriesQuery,
    addCountry: addMutation.mutateAsync,
    removeCountry: removeMutation.mutateAsync,
    isAdding: addMutation.isPending,
    isRemoving: removeMutation.isPending,
  };
};

// SSE Events hook — connects to /api/v1/events with token as query param
export const useSseEvents = () => {
  const [events, setEvents] = useState<Event[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  useEffect(() => {
    const token = sessionStorage.getItem('ja4proxy_token');
    const url = token
      ? `/api/v1/events?key=${encodeURIComponent(token)}`
      : '/api/v1/events';
    const eventSource = new EventSource(url);

    eventSource.onopen = () => {
      setIsConnected(true);
    };

    eventSource.onmessage = (e) => {
      try {
        const eventData = JSON.parse(e.data);
        setEvents((prev) => [eventData, ...prev].slice(0, 100));
      } catch {
        // ignore parse errors
      }
    };

    eventSource.onerror = () => {
      setIsConnected(false);
    };

    return () => {
      eventSource.close();
      setIsConnected(false);
    };
  }, []);

  return { events, isConnected };
};
