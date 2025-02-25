"use client";

import { api } from '@/lib/api-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { User } from '@/app/types/user';
import { useState } from 'react';

export function AddUser() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [errors, setErrors] = useState<{ email?: string; password?: string }>({});
    const { toast } = useToast();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            const user = {
                email,
                password,
                profile: {
                    first_name,
                    j
                }
            };
            const response = await api.auth.register(user);
            console.log('User created:', response);
            toast({
                title: '成功',
                description: 'ユーザーが作成されました',
            });
        } catch (error: any) {
            if (error.response?.status === 422) {
                setErrors(error.response.data.errors);
            } else {
                toast({
                    title: 'エラー',
                    description: error.message || 'ユーザーの作成に失敗しました',
                    variant: 'destructive',
                });
            }
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <Input
                type="email"
                label="メールアドレス"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                error={errors.email}
            />
            <Input
                type="password"
                label="パスワード"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                error={errors.password}
            />
            <Button type="submit" isLoading={isLoading}>
                作成
            </Button>
        </form>
    );
}