// types/user.ts
export interface User {
    id: string;
    email: string;
    first_name?: string;
    last_name?: string;
    name?: string;
    role?: string;
    active: boolean;
    profile_pic?: string;
    phone?: string;
    department?: string;
    joined_date?: string;
    last_login?: string;
    permissions?: string[];
}

export interface AuthResponse {
    user: User;
    token: string;
}

export interface LoginCredentials {
    email: string;
    password: string;
}

export interface PasskeyCredential {
    id: string;
    rawId: string;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string;
    };
    type: 'public-key';
}

// Add any other related types here
export interface UserAuthMethod {
    id: string;
    type: 'password' | 'passkey' | 'biometric' | 'sso';
    is_preferred: boolean;
    metadata?: Record<string, any>;
    created_at: string;
    last_used_at?: string;
}