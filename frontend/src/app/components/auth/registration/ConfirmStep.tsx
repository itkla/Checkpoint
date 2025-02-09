import { useState } from 'react';
import { StepLayout } from './StepLayout';
import { Button } from '@/components/ui/button';
import { AuthState } from '@/app/types/auth';
import { api } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import { useRouter } from 'next/navigation';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

interface ConfirmStepProps {
    registrationData: AuthState;
    onBack: () => void;
    onComplete: () => void;
}

export function ConfirmStep({
    registrationData,
    onBack,
    onComplete,
}: ConfirmStepProps) {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [requiresVerification, setRequiresVerification] = useState(false);
    const { toast } = useToast();
    const router = useRouter();

    const handleSubmit = async () => {
        setIsSubmitting(true);
        try {
            const response = await api.auth.register(registrationData);

            if (response.requiresVerification) {
                setRequiresVerification(true);
                toast({
                    title: "確認メールを送信しました",
                    description: "メールに記載されたリンクをクリックして、登録を完了してください",
                });
            } else {
                localStorage.setItem('token', response.token);
                onComplete();
                router.push('/dashboard');
            }
        } catch (error: any) {
            toast({
                title: "エラー",
                description: error.response?.data?.error || "登録に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsSubmitting(false);
        }
    };

    if (requiresVerification) {
        return (
            <StepLayout
                title="メール確認"
                description="確認メールをお送りしました"
                showBack={false}
            >
                <div className="text-center space-y-4">
                    <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-yellow-500" />
                    <p className="text-gray-600">
                        {registrationData.email} に確認メールをお送りしました。
                        メールに記載されたリンクをクリックして、登録を完了してください。
                    </p>
                    <Button
                        variant="outline"
                        onClick={() => router.push('/login')}
                    >
                        ログイン画面へ
                    </Button>
                </div>
            </StepLayout>
        );
    }

    return (
        <StepLayout
            title="登録内容の確認"
            description="入力内容を確認してください"
            onBack={onBack}
        >
            <div className="space-y-6">
                <div className="bg-gray-50 rounded-lg p-6 space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <h3 className="text-sm font-medium text-gray-500">メールアドレス</h3>
                            <p className="mt-1">{registrationData.email}</p>
                        </div>
                        <div>
                            <h3 className="text-sm font-medium text-gray-500">認証方法</h3>
                            <p className="mt-1">
                                {registrationData.authMethod === 'password' && 'パスワード'}
                                {registrationData.authMethod === 'passkey' && 'パスキー'}
                                {registrationData.authMethod === 'sso' && 'SSO認証'}
                            </p>
                        </div>
                        {registrationData.profile && (
                            <>
                                <div>
                                    <h3 className="text-sm font-medium text-gray-500">氏名</h3>
                                    <p className="mt-1">
                                        {registrationData.profile.lastName} {registrationData.profile.firstName}
                                    </p>
                                </div>
                                {registrationData.profile.department && (
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-500">部署</h3>
                                        <p className="mt-1">{registrationData.profile.department}</p>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </div>

                <div className="flex justify-between">
                    <Button variant="ghost" onClick={onBack} disabled={isSubmitting}>
                        戻る
                    </Button>
                    <Button
                        onClick={handleSubmit}
                        disabled={isSubmitting}
                        className="min-w-[120px]"
                    >
                        {isSubmitting ? '登録中...' : '登録'}
                    </Button>
                </div>
            </div>
        </StepLayout>
    );
}