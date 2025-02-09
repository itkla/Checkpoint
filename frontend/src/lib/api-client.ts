// lib/api-client.ts
import axios from 'axios';
import type {
    User,
    AuthResponse,
    LoginCredentials,
    PasskeyCredential,
    UserAuthMethod
} from '@/app/types/user';
import { register } from 'module';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

const apiClient = axios.create({
    baseURL: API_URL,
    withCredentials: true,
});

apiClient.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

export const authApi = {
    login: async (credentials: LoginCredentials) => {
        const response = await apiClient.post<AuthResponse>('/api/auth/login', credentials);
        return response.data;
    },

    initiatePasskey: async (email: string) => {
        const response = await apiClient.post<PublicKeyCredentialRequestOptions>(
            '/api/auth/passkey/login/start',
            { email }
        );
        return response.data;
    },

    completePasskey: async (email: string, credential: PasskeyCredential) => {
        const response = await apiClient.post<AuthResponse>(
            '/api/auth/passkey/login/complete',
            { email, credential }
        );
        return response.data;
    },

    registerPasskey: async () => {
        const response = await apiClient.post<PublicKeyCredentialCreationOptions>(
            '/api/auth/passkey/register/start'
        );
        return response.data;
    },

    completePasskeyRegistration: async (credential: PasskeyCredential) => {
        const response = await apiClient.post<{ success: boolean }>(
            '/api/auth/passkey/register/complete',
            credential
        );
        return response.data;
    },

    register: async (data: Partial<User>) => {
        const response = await apiClient.post<AuthResponse>('/api/auth/register', data);
        return response.data;
    },

    forgotPassword: async (email: string) => {
        const response = await apiClient.post<{ success: boolean }>('/api/auth/password-reset', {
            email,
        });
        return response.data;
    },

    verifyEmail: async (token: string) => {
        const response = await apiClient.post('/api/auth/verify-email', { token });
        return response.data;
    },

    resendVerification: async (email: string) => {
        const response = await apiClient.post('/api/auth/resend-verification', { email });
        return response.data;
    },

    verify2FA: async (code: string) => {
        const response = await apiClient.post('/api/auth/verify-2fa', { code });
        return response.data;
    },

    generateRecoveryCodes: async () => {
        const response = await apiClient.post('/api/auth/recovery-codes');
        return response.data;
    },

    useRecoveryCode: async (code: string) => {
        const response = await apiClient.post('/api/auth/use-recovery-code', { code });
        return response.data;
    },

    initiate2FA: async () => {
        const response = await apiClient.post('/api/auth/2fa/setup');
        return response.data;
    },

    disable2FA: async (code: string) => {
        const response = await apiClient.post('/api/auth/2fa/disable', { code });
        return response.data;
    },
};

export const userApi = {
    getUsers: async (search?: string, page = 1, pageSize = 10) => {
        const response = await apiClient.get<User[]>('/api/users', {
            params: { search, page, pageSize },
        });
        return response.data;
    },

    getUser: async (id: string) => {
        const response = await apiClient.get<User>(`/api/users/${id}`);
        return response.data;
    },

    updateUser: async (id: string, data: Partial<User>) => {
        const response = await apiClient.put<User>(`/api/users/${id}`, data);
        return response.data;
    },

    deleteUser: async (id: string) => {
        const response = await apiClient.delete<{ success: boolean; userId: string }>(
            `/api/users/${id}`
        );
        return response.data;
    },

    getUserAuthMethods: async (id: string) => {
        const response = await apiClient.get<UserAuthMethod[]>(
            `/api/users/${id}/auth-methods`
        );
        return response.data;
    },

    userExists: async (email: string) => {
        const response = await apiClient.get<{ exists: boolean }>(
            `/api/users/exists?email=${email}`
        );
        return response.data;
    },
};

// Export a unified API object
export const api = {
    auth: authApi,
    users: userApi,
};

export default api;