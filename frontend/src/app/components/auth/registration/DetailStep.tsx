import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { passwordSchema } from '@/app/types/auth';
import { startRegistration } from '@simplewebauthn/browser';
import { StepLayout } from './StepLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SecurityChecklist } from './SecurityChecklist';
import { PasswordStrengthMeter } from './PasswordStrengthMeter';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';

interface DetailsStepProps {
    authMethod: 'password' | 'passkey' | 'sso';
    onNext: (data: any) => void;
    onBack: () => void;
}

export function DetailStep({ authMethod, onNext, onBack }: DetailsStepProps) {
    const [isProcessing, setIsProcessing] = useState(false);
    const { toast } = useToast();
    const form = useForm({
        resolver: zodResolver(passwordSchema),
        defaultValues: {
            password: '',
            confirmPassword: '',
        },
    });

    // if (form.formState.errors.password) {
    //     toast({
    //         title: "エラー",
    //         description: "パスワードが無効です: " + form.formState.errors.password.message,
    //         variant: "destructive",
    //     });
    // }

    const handlePasskeyRegistration = async () => {
        setIsProcessing(true);
        try {
            const options = await api.auth.registerPasskey();
            const credential = await startRegistration(options);
            const verification = await api.auth.completePasskeyRegistration(credential);

            if (verification.success) {
                onNext({ passkeyCredential: credential });
            } else {
                throw new Error('パスキーの登録に失敗しました');
            }
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスキーの登録に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsProcessing(false);
        }
    };

    if (authMethod === 'passkey') {
        return (
            <StepLayout
                title="パスキーの設定"
                description="デバイスの生体認証やセキュリティ機能を使用してパスキーを設定します"
                onBack={onBack}
            >
                <div className="space-y-6">
                    <Button
                        onClick={handlePasskeyRegistration}
                        className="w-full py-6"
                        disabled={isProcessing}
                    >
                        {isProcessing ? 'パスキーを設定中...' : 'パスキーを設定'}
                    </Button>
                </div>
            </StepLayout>
        );
    }

    if (authMethod === 'password') {
        const password = form.watch('password');

        return (
            <StepLayout
                title="パスワードの設定"
                description="安全なパスワードを設定してください"
                onBack={onBack}
            >
                <form onSubmit={form.handleSubmit(onNext)} className="space-y-6">
                    <div className="space-y-4">
                        <Input
                            type="password"
                            placeholder="パスワード"
                            {...form.register('password')}
                        />
                        <PasswordStrengthMeter password={password} />
                        <SecurityChecklist password={password} />

                        <Input
                            type="password"
                            placeholder="パスワード (確認)"
                            {...form.register('confirmPassword')}
                        />
                        {form.formState.errors.confirmPassword && (
                            <p className="text-sm text-red-500">
                                {form.formState.errors.confirmPassword.message}
                            </p>
                        )}
                    </div>

                    <Button type="submit" className="w-full">
                        次へ
                    </Button>
                </form>
                <Button type="button" variant="ghost" onClick={onBack}>
                    戻る
                </Button>
            </StepLayout>
        );
    }

    return null; // SSO doesn't need additional setup
}