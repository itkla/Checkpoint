// types/user.ts
export interface User {
    id: string;
    email: string;
    // name?: string;
    role?: string;
    active: boolean;
    profile?: {
        first_name?: string;
        last_name?: string;
        profile_pic?: string;
        phone?: string;
        dateOfBirth?: Date;
        address?: {
            street?: string;
            street2?: string;
            city?: string;
            state?: string;
            zip?: string;
            country?: string;
        }
    }
    department?: string;
    joined_date?: string;
    last_login?: string;
    permissions?: string[];
    password_changed_at?: string;
}

export interface AuthResponse {
    user: {
        id: string;
        email: string;
    };
    token: string;
    requiresVerification?: boolean;
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

export interface UserProfile {
    id: string;
    user_id: string;
    first_name: string;
    last_name: string;
    phone: string;
    department: string;
    profile_pic: string;
    created_at: string;
    updated_at: string;
    dateOfBirth: Date;
}

export interface UserActivityLog {
    id: string;
    type: 'login' | 'password_change' | 'profile_update' | 'security_event';
    description: string;
    timestamp: string;
    metadata?: Record<string, any>;
}

export interface UserPasswordReset {
    email: string;
    token: string;
    expires_at: string;
}

export interface UserVerification {
    email: string;
    token: string;
    expires_at: string;
}

export interface UserRegistration {
    email: string;
    token: string;
    expires_at: string;
}

export interface UserSession {
    id: string;
    user_id: string;
    user_agent: string;
    ip_address: string;
    last_used_at: string;
    created_at: string;
}