export interface ApiUser {
    id: string;
    email: string;
    first_name?: string;
    last_name?: string;
    profile_pic?: string;
    role?: string;
    active?: boolean;
}

export interface AuthResponse {
    user: ApiUser;
    token: string;
}