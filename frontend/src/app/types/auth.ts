// types/auth.ts
import { z } from "zod";

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
    password: z
        .string()
        .min(8, "パスワードは8文字以上である必要があります")
        .max(72, "パスワードが長すぎます")
        .regex(/[A-Z]/, "パスワードは少なくとも1つの大文字を含む必要があります")
        .regex(/[a-z]/, "パスワードは少なくとも1つの小文字を含む必要があります")
        .regex(/[0-9]/, "パスワードは少なくとも1つの数字を含む必要があります")
        .regex(/[@$!%*?&]/, "パスワードは少なくとも1つの特殊文字を含む必要があります")
        .regex(passwordPattern, "パスワードが要件を満たしていません"),
    confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
    message: "パスワードが一致しません",
    path: ["confirmPassword"],
});

// User profile schema
export const userProfileSchema = z.object({
    firstName: z.string().min(1, "名前は必須です").max(50, "名前が長すぎます"),
    lastName: z.string().min(1, "姓は必須です").max(50, "姓が長すぎます"),
    phone: z.string().regex(phonePattern, "有効な電話番号を入力してください").optional(),
    department: z.string().max(100, "部署名が長すぎます").optional(),
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