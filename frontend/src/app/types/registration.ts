import { z } from "zod";

export const emailSchema = z.object({
    email: z
        .string()
        .email("有効なメールアドレスを入力してください")
        .min(1, "メールアドレスは必須です"),
});

export const passwordSchema = z.object({
    password: z
        .string()
        .min(8, "パスワードは8文字以上である必要があります")
        .regex(/[A-Z]/, "パスワードは少なくとも1つの大文字を含む必要があります")
        .regex(/[a-z]/, "パスワードは少なくとも1つの小文字を含む必要があります")
        .regex(/[0-9]/, "パスワードは少なくとも1つの数字を含む必要があります"),
    confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
    message: "パスワードが一致しません",
    path: ["confirmPassword"],
});

export type RegistrationData = {
    email: string;
    authMethod: 'password' | 'passkey' | 'sso';
    password?: string;
    ssoProvider?: 'google' | 'line';
};

export type RegistrationStep = 'email' | 'method' | 'details' | 'confirm';