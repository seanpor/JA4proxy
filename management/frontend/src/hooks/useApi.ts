import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';

// Types for API responses
interface Ban {
  id: string;
  ip: string;
  reason: string;
  expires_at: string;
  created_at: string;
}

interface CIDR {
  id: string;
  cidr: string;
  reason: string;
  created_at: string;
}

interface Fingerprint {
  id: string;
  fingerprint: string;
  tag: string;
  created_at: string;
}

interface ThresholdConfig {
  ban_threshold: number;
  fingerprint_threshold: number;
  cidr_threshold: number;
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
  version: string;
  uptime: number;
  redis_connected: boolean;
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
    return response.data;
  };

  const createBan = async (banData: Omit<Ban, 'id' | 'created_at'>): Promise<Ban> => {
    const response = await apiClient.post('/bans', banData);
    return response.data;
  };

  const deleteBan = async (id: string): Promise<void> => {
    await apiClient.delete(`/bans/${id}`);
  };

  const bansQuery = useQuery<Ban[], Error>({
    queryKey: ['bans'],
    queryFn: getBans,
  });

  const createBanMutation = useMutation<Ban, Error, Omit<Ban, 'id' | 'created_at'>>({
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
    return response.data;
  };

  const createCIDR = async (cidrData: Omit<CIDR, 'id' | 'created_at'>): Promise<CIDR> => {
    const response = await apiClient.post('/cidrs', cidrData);
    return response.data;
  };

  const deleteCIDR = async (id: string): Promise<void> => {
    await apiClient.delete(`/cidrs/${id}`);
  };

  const cidrsQuery = useQuery<CIDR[], Error>({
    queryKey: ['cidrs'],
    queryFn: getCIDRs,
  });

  const createCIDRMutation = useMutation<CIDR, Error, Omit<CIDR, 'id' | 'created_at'>>({
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
    const response = await apiClient.get('/fingerprints');
    return response.data;
  };

  const createFingerprint = async (fingerprintData: Omit<Fingerprint, 'id' | 'created_at'>): Promise<Fingerprint> => {
    const response = await apiClient.post('/fingerprints', fingerprintData);
    return response.data;
  };

  const deleteFingerprint = async (id: string): Promise<void> => {
    await apiClient.delete(`/fingerprints/${id}`);
  };

  const fingerprintsQuery = useQuery<Fingerprint[], Error>({
    queryKey: ['fingerprints'],
    queryFn: getFingerprints,
  });

  const createFingerprintMutation = useMutation<Fingerprint, Error, Omit<Fingerprint, 'id' | 'created_at'>>({
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
  const getAuditLog = async (): Promise<{ data: AuditLogEntry[]; total: number }> => {
    const response = await apiClient.get('/audit', {
      params: { page, page_size: pageSize }
    });
    return response.data;
  };

  return useQuery<{ data: AuditLogEntry[]; total: number }, Error>({
    queryKey: ['auditLog', page, pageSize],
    queryFn: getAuditLog,
  });
};

// Health hooks
export const useHealth = () => {
  const getHealth = async (): Promise<HealthStatus> => {
    const response = await apiClient.get('/health');
    return response.data;
  };

  return useQuery<HealthStatus, Error>({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 30000, // Refetch every 30 seconds
  });
};

// Dial (counterfactual) hooks
export const useDial = () => {
  const dial = async (fingerprint: string): Promise<any> => {
    const response = await apiClient.post('/dial', { fingerprint });
    return response.data;
  };

  return useMutation<any, Error, string>({
    mutationFn: dial,
  });
};

// SSE Events hook
export const useSseEvents = () => {
  const [events, setEvents] = useState<Event[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  useEffect(() => {
    const eventSource = new EventSource('/events/sse');

    eventSource.onopen = () => {
      console.log('SSE connection opened');
      setIsConnected(true);
    };

    eventSource.onmessage = (e) => {
      try {
        const eventData = JSON.parse(e.data);
        setEvents((prev) => [eventData, ...prev].slice(0, 100)); // Keep last 100 events
      } catch (error) {
        console.error('Error parsing SSE event:', error);
      }
    };

    eventSource.onerror = (e) => {
      console.error('SSE error:', e);
      setIsConnected(false);
    };

    return () => {
      eventSource.close();
      setIsConnected(false);
    };
  }, []);

  return { events, isConnected };
};