"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useSseEvents = exports.useDial = exports.useHealth = exports.useAuditLog = exports.useThresholdConfig = exports.useFingerprints = exports.useCIDRs = exports.useBans = void 0;
const react_1 = require("react");
const react_query_1 = require("@tanstack/react-query");
const client_1 = require("../api/client");
// Ban hooks
const useBans = () => {
    const queryClient = (0, react_query_1.useQueryClient)();
    const getBans = async () => {
        const response = await client_1.apiClient.get('/bans');
        return response.data;
    };
    const createBan = async (banData) => {
        const response = await client_1.apiClient.post('/bans', banData);
        return response.data;
    };
    const deleteBan = async (id) => {
        await client_1.apiClient.delete(`/bans/${id}`);
    };
    const bansQuery = (0, react_query_1.useQuery)({
        queryKey: ['bans'],
        queryFn: getBans,
    });
    const createBanMutation = (0, react_query_1.useMutation)({
        mutationFn: createBan,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['bans'] });
        },
    });
    const deleteBanMutation = (0, react_query_1.useMutation)({
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
exports.useBans = useBans;
// CIDR hooks
const useCIDRs = () => {
    const queryClient = (0, react_query_1.useQueryClient)();
    const getCIDRs = async () => {
        const response = await client_1.apiClient.get('/cidrs');
        return response.data;
    };
    const createCIDR = async (cidrData) => {
        const response = await client_1.apiClient.post('/cidrs', cidrData);
        return response.data;
    };
    const deleteCIDR = async (id) => {
        await client_1.apiClient.delete(`/cidrs/${id}`);
    };
    const cidrsQuery = (0, react_query_1.useQuery)({
        queryKey: ['cidrs'],
        queryFn: getCIDRs,
    });
    const createCIDRMutation = (0, react_query_1.useMutation)({
        mutationFn: createCIDR,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['cidrs'] });
        },
    });
    const deleteCIDRMutation = (0, react_query_1.useMutation)({
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
exports.useCIDRs = useCIDRs;
// Fingerprint hooks
const useFingerprints = () => {
    const queryClient = (0, react_query_1.useQueryClient)();
    const getFingerprints = async () => {
        const response = await client_1.apiClient.get('/fingerprints');
        return response.data;
    };
    const createFingerprint = async (fingerprintData) => {
        const response = await client_1.apiClient.post('/fingerprints', fingerprintData);
        return response.data;
    };
    const deleteFingerprint = async (id) => {
        await client_1.apiClient.delete(`/fingerprints/${id}`);
    };
    const fingerprintsQuery = (0, react_query_1.useQuery)({
        queryKey: ['fingerprints'],
        queryFn: getFingerprints,
    });
    const createFingerprintMutation = (0, react_query_1.useMutation)({
        mutationFn: createFingerprint,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['fingerprints'] });
        },
    });
    const deleteFingerprintMutation = (0, react_query_1.useMutation)({
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
exports.useFingerprints = useFingerprints;
// Threshold config hooks
const useThresholdConfig = () => {
    const queryClient = (0, react_query_1.useQueryClient)();
    const getThresholdConfig = async () => {
        const response = await client_1.apiClient.get('/config/thresholds');
        return response.data;
    };
    const updateThresholdConfig = async (config) => {
        const response = await client_1.apiClient.put('/config/thresholds', config);
        return response.data;
    };
    const thresholdConfigQuery = (0, react_query_1.useQuery)({
        queryKey: ['thresholdConfig'],
        queryFn: getThresholdConfig,
    });
    const updateThresholdConfigMutation = (0, react_query_1.useMutation)({
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
exports.useThresholdConfig = useThresholdConfig;
// Audit log hooks
const useAuditLog = (page = 1, pageSize = 50) => {
    const getAuditLog = async () => {
        const response = await client_1.apiClient.get('/audit', {
            params: { page, page_size: pageSize }
        });
        return response.data;
    };
    return (0, react_query_1.useQuery)({
        queryKey: ['auditLog', page, pageSize],
        queryFn: getAuditLog,
    });
};
exports.useAuditLog = useAuditLog;
// Health hooks
const useHealth = () => {
    const getHealth = async () => {
        const response = await client_1.apiClient.get('/health');
        return response.data;
    };
    return (0, react_query_1.useQuery)({
        queryKey: ['health'],
        queryFn: getHealth,
        refetchInterval: 30000, // Refetch every 30 seconds
    });
};
exports.useHealth = useHealth;
// Dial (counterfactual) hooks
const useDial = () => {
    const dial = async (fingerprint) => {
        const response = await client_1.apiClient.post('/dial', { fingerprint });
        return response.data;
    };
    return (0, react_query_1.useMutation)({
        mutationFn: dial,
    });
};
exports.useDial = useDial;
// SSE Events hook
const useSseEvents = () => {
    const [events, setEvents] = (0, react_1.useState)([]);
    const [isConnected, setIsConnected] = (0, react_1.useState)(false);
    (0, react_1.useEffect)(() => {
        const eventSource = new EventSource('/events/sse');
        eventSource.onopen = () => {
            console.log('SSE connection opened');
            setIsConnected(true);
        };
        eventSource.onmessage = (e) => {
            try {
                const eventData = JSON.parse(e.data);
                setEvents((prev) => [eventData, ...prev].slice(0, 100)); // Keep last 100 events
            }
            catch (error) {
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
exports.useSseEvents = useSseEvents;
