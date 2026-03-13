"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.apiClient = void 0;
const axios_1 = __importDefault(require("axios"));
// API base URL
const API_BASE_URL = '/api/v1';
// Create axios instance
const apiClient = axios_1.default.create({
    baseURL: API_BASE_URL,
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json'
    }
});
exports.apiClient = apiClient;
// Request interceptor - add auth token
apiClient.interceptors.request.use((config) => {
    const token = sessionStorage.getItem('ja4proxy_token');
    if (token) {
        config.headers = config.headers || {};
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}, (error) => {
    return Promise.reject(error);
});
// Response interceptor - handle errors
apiClient.interceptors.response.use((response) => response, (error) => {
    if (error.response?.status === 401) {
        // Clear token and redirect to login
        sessionStorage.removeItem('ja4proxy_token');
        window.location.href = '/login';
    }
    return Promise.reject(error);
});
