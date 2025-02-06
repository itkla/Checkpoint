interface LoginResponse {
    mfa?: boolean;
    mfaToken?: string;
    token?: string;
    error?: string;
}

interface MFARequest {
    mfaToken: string;
    code: string;
}