'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { resetPasswordSchema } from '@/app/types/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { SecurityChecklist } from '@/app/components/auth/registration/SecurityChecklist';
import { PasswordStrengthMeter } from '@/app/components/auth/registration/PasswordStrengthMeter';
import { api } from '@/lib/api-client';
import { useRouter } from 'next/navigation';

export default function ResetPasswordPage({
    params: { token },
}: {
    params: { token: string };
}) {
    const [isLoading, setIsLoading] = useState(false);
    const { toast } = useToast();
    const router = useRouter();
    const form = useForm({
        resolver: zodResolver(resetPasswordSchema),
        defaultValues: {
            token,
            newPassword: '',
            confirmPassword: '',
        },
    });

    const onSubmit = async (data: { newPassword: string }) => {
        setIsLoading(true);
        try {
            await api.auth.resetPassword({
                token,
                newPassword: data.newPassword,
            });
            toast({
                title: "成功",
                description: "パスワードが正常に変更されました",
            });
            router.push('/login');
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスワードの変更に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoading(false);
        }
    };

    const password = form.watch('newPassword');

    return (
        <div className="container flex justify-center items-center min-h-screen">
            <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-[5%]">
                <h1 className="text-2xl font-bold text-center">新しいパスワードの設定</h1>
                <p className="mt-2 text-gray-600 text-center">
                    新しいパスワードを入力してください
                </p>

                <form onSubmit={form.handleSubmit(onSubmit)} className="mt-8 space-y-6">
                    <div className="space-y-4">
                        <Input
                            {...form.register('newPassword')}
                            type="password"
                            placeholder="新しいパスワード"
                        />
                        <PasswordStrengthMeter password={password} />
                        <SecurityChecklist password={password} />

                        <Input
                            {...form.register('confirmPassword')}
                            type="password"
                            placeholder="パスワード (確認)"
                        />
                        {form.formState.errors.confirmPassword && (
                            <p className="text-sm text-red-500">
                                {form.formState.errors.confirmPassword.message}
                            </p>
                        )}
                    </div>

                    <Button
                        type="submit"
                        className="w-full py-6"
                        disabled={isLoading}
                    >
                        {isLoading ? '変更中...' : 'パスワードを変更'}
                    </Button>
                </form>
            </div>
        </div>
    );
}