import * as z from 'zod';

const LoginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

type LoginSchemaType = z.infer<typeof LoginSchema>;

export { LoginSchema, LoginSchemaType };