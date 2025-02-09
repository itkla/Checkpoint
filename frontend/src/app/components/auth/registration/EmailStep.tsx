import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { emailSchema } from '@/app/types/auth';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { StepLayout } from './StepLayout';
import { api } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';

interface EmailStepProps {
    initialEmail: string;
    onNext: (email: string) => void;
}

export function EmailStep({ initialEmail, onNext }: EmailStepProps) {
    const [isChecking, setIsChecking] = useState(false);
    const { toast } = useToast();
    const form = useForm({
        resolver: zodResolver(emailSchema),
        defaultValues: {
            email: initialEmail,
        },
    });

    const onSubmit = async (data: { email: string }) => {
        setIsChecking(true);
        try {
            // Check if email already exists
            const response = await api.users.userExists(data.email);
            if (response.exists) {
                toast({
                    title: "エラー",
                    description: "このメールアドレスは既に登録されています",
                    variant: "destructive",
                });
                return;
            }
            onNext(data.email);
        } catch (error) {
            toast({
                title: "エラー",
                description: "メールアドレスの確認に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsChecking(false);
        }
    };

    return (
        <StepLayout
            title="メールアドレスを入力"
            description="アカウントに使用するメールアドレスを入力してください"
            showBack={false}
        >
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <Input
                    {...form.register('email')}
                    type="email"
                    placeholder="example@example.com"
                    className="text-lg"
                    disabled={isChecking}
                />
                {form.formState.errors.email && (
                    <p className="text-sm text-red-500">
                        {form.formState.errors.email.message}
                    </p>
                )}
                <Button
                    type="submit"
                    className="w-full py-6"
                    disabled={isChecking}
                >
                    {isChecking ? '確認中...' : '次へ'}
                </Button>
            </form>
        </StepLayout>
    );
}