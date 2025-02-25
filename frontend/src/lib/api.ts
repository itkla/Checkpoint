import {User} from '@/app/types/user';
import { headers } from 'next/headers';
import { LoginCredentials } from '@/app/types/user';
import { AuthResponse } from '@/app/types/auth';
import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://localhost:3001';

const apiClient = axios.create({
    baseURL: API_URL,
    withCredentials: true,
});

apiClient.interceptors.request.use(async (config) => {
    const requestHeaders = await headers();
    const token = requestHeaders.get('x-checkpoint-token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// authentication API

export async function login(credentials: LoginCredentials): Promise<AuthResponse> {
    // console.log('Sending credentials:', credentials); // Debug log
    const response = await apiClient.post<AuthResponse>('/api/auth/login', credentials);
    return response.data;
}

