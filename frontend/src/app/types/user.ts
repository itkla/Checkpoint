import { z } from "zod";

export const userSchema = z.object({
    id: z.string().optional(),
    name: z.string().min(1, "名前は必須です"),
    email: z.string().email("有効なメールアドレスを入力してください"),
    role: z.enum(["Admin", "Editor", "Viewer"], {
        required_error: "役割を選択してください",
    }),
    active: z.boolean(),
    profile_pic: z.string().url().optional(),
    department: z.string().optional(),
    phone: z.string().regex(/^[0-9-+\s()]*$/, "無効な電話番号形式です").optional(),
    joined_date: z.string().optional(),
    last_login: z.string().optional(),
    permissions: z.array(z.string()).optional(),
});

export type User = z.infer<typeof userSchema>;