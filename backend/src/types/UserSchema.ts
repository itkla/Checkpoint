import { z } from 'zod';

const UserSchema = z.object({
    id: z.string().optional(),
    email: z.string().email(),
    password: z.string().min(8).optional(),
    profile: z.object({
        address: z.object({
            street: z.string().optional(),
            street2: z.string().optional(),
            city: z.string().optional(),
            state: z.string().optional(),
            zip: z.string().optional(),
            country: z.string().optional(),
        }).optional(),
        department: z.string().optional(),
        dateOfBirth: z.union([
            z.date(),
            z.string()
              .refine(str => !isNaN(Date.parse(str)), {
                message: "Invalid date string"
              })
              .transform(str => new Date(str))
          ]).optional(),
        first_name: z.string().optional(),
        last_name: z.string().optional(),
        profile_pic: z.string().optional(),
        phone: z.string().optional(),
        profile_picture: z.string().optional(),
    }),
    public_key: z.string().optional(),
    private_key: z.string().optional(),
    authMethod: z.string().optional(),
    confirmPassword: z.string().optional(),
    password_changed_at: z.date().optional(),
    created_at: z.date().optional(),
    two_factor_enabled: z.boolean().optional(),
});

export { UserSchema };
export type UserSchemaType = z.infer<typeof UserSchema>;