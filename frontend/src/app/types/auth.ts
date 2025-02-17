// types/auth.ts
import { date, z } from "zod";
import { isPasswordValid } from "@/lib/passwordValidation";

// Basic validation patterns
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const phonePattern = /^(\+?\d{1,4}[-.\s]?)?(\(?\d{1,3}\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}$/;

// Email validation schema
export const emailSchema = z.object({
    email: z
        .string()
        .email("有効なメールアドレスを入力してください")
        .min(1, "メールアドレスは必須です")
        .max(255, "メールアドレスが長すぎます"),
});

// Password validation schema with enhanced rules
export const passwordSchema = z.object({
    password: z.string().refine(val => isPasswordValid(val), {
        message: "パスワードは8文字以上で、大文字、小文字、数字、特殊文字を含む必要があります",
    }),
    confirmPassword: z.string(),
}).refine(data => data.password === data.confirmPassword, {
    message: "パスワードが一致しません",
    path: ["confirmPassword"],
});

// User profile schema
export const userProfileSchema = z.object({
    first_name: z.string().min(1, "名前は必須です").max(50, "名前が長すぎます"),
    last_name: z.string().min(1, "姓は必須です").max(50, "姓が長すぎます"),
    phone: z.string().regex(phonePattern, "有効な電話番号を入力してください").optional(),
    department: z.string().max(100, "部署名が長すぎます").optional(),
    profile_pic: z.string().optional(),
    dateOfBirth: date().optional(),
    address: z.object({
        street: z.string().optional(),
        street2: z.string().optional(),
        city: z.string().optional(),
        state: z.string().optional(),
        zip: z.string().optional(),
        country: z.string().optional(),
    }).optional()
});

// Combined registration schema
export const registrationSchema = emailSchema.merge(passwordSchema.innerType()).merge(userProfileSchema);

// Types derived from schemas
export type EmailData = z.infer<typeof emailSchema>;
export type PasswordData = z.infer<typeof passwordSchema>;
export type UserProfileData = z.infer<typeof userProfileSchema>;
export type RegistrationData = z.infer<typeof registrationSchema>;

// Authentication method types
export type AuthMethod = 'password' | 'passkey' | 'sso';
export type SsoProvider = 'google' | 'line';

export interface AuthState {
    email: string;
    authMethod: AuthMethod;
    ssoProvider?: SsoProvider;
    password?: string;
    profile?: UserProfileData;
    passkeyCredential?: any;
}

// Progress tracking
export type RegistrationStep = 'email' | 'method' | 'profile' | 'details' | 'confirm';

export interface StepConfig {
    key: RegistrationStep;
    title: string;
    description: string;
}

export const registrationSteps: StepConfig[] = [
    {
        key: 'email',
        title: 'メールアドレス',
        description: 'アカウントに使用するメールアドレスを入力してください',
    },
    {
        key: 'method',
        title: '認証方法',
        description: 'ログインに使用する認証方法を選択してください',
    },
    {
        key: 'profile',
        title: 'プロフィール',
        description: '基本情報を入力してください',
    },
    {
        key: 'details',
        title: '詳細設定',
        description: '認証情報を設定してください',
    },
    {
        key: 'confirm',
        title: '確認',
        description: '入力内容を確認してください',
    },
];

// Password reset types
export interface ResetPasswordData {
    token: string;
    newPassword: string;
}

export const resetPasswordSchema = z.object({
    token: z.string(),
    newPassword: passwordSchema.innerType().shape.password,
    confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "パスワードが一致しません",
    path: ["confirmPassword"],
});

// Error types
export interface ApiError {
    message: string;
    code: string;
    details?: Record<string, string[]>;
}

export interface ValidationError {
    field: string;
    message: string;
}

export interface LoginCredentials {
    email: string;
    password: string;
}

export interface AuthResponse {
    user: {
        id: string;
        email: string;
    };
    token: string;
    requiresVerification?: boolean;
    twoFactorRequired?: boolean;
    tempToken?: string;
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