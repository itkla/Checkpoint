import { useState } from 'react';
import { StepLayout } from './StepLayout';
import { Button } from '@/components/ui/button';
import { AuthState } from '@/app/types/auth';
import { api } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import { useRouter, useSearchParams } from 'next/navigation';
import Image from 'next/image';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

interface ConfirmStepProps {
    registrationData: AuthState & { profilePicture?: File; preview?: string };
    onBack: () => void;
    onComplete: () => void;
}

export function ConfirmStep({
    registrationData,
    onBack,
    onComplete,
}: ConfirmStepProps) {
    // get 'next' url param to redirect client after successful registration
    const searchParams = useSearchParams();
    const next = searchParams.get('next');

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [requiresVerification, setRequiresVerification] = useState(false);
    const { toast } = useToast();
    const router = useRouter();

    // Function to upload the profile picture using FormData.
    async function uploadProfilePicture(userId: string, file: File) {
        // Pass the File object directly to the API method
        const response = await api.users.uploadProfilePicture(file, userId);
        return response;
    }
    console.log(registrationData);

    const handleSubmit = async () => {
        setIsSubmitting(true);
        try {
            // Registration API call
            const response = await api.auth.register(registrationData);
            if (response.requiresVerification) {
                setRequiresVerification(true);
                toast({
                    title: "確認メールを送信しました",
                    description: "メールに記載されたリンクをクリックして、登録を完了してください",
                });
            } else {
                localStorage.setItem('token', response.token);

                // If there is a profile picture, upload it
                if (registrationData.profilePicture) {
                    try {
                        await uploadProfilePicture(response.user.id, registrationData.profilePicture);
                    } catch (uploadError) {
                        toast({
                            title: "画像アップロードエラー",
                            description: "プロフィール画像のアップロードに失敗しました",
                            variant: "destructive",
                        });
                        console.error("Profile picture upload failed", uploadError);
                    }
                }

                onComplete();
                if (next) {
                    router.push(next);
                } else {
                    router.push('/me');
                }
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
            <StepLayout title="メール確認" description="確認メールをお送りしました" showBack={false}>
                <div className="text-center space-y-4">
                    <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-yellow-500" />
                    <p className="text-gray-600">
                        {registrationData.email} に確認メールをお送りしました。
                        メールに記載されたリンクをクリックして、登録を完了してください。
                    </p>
                    <Button variant="outline" onClick={() => router.push('/login')}>
                        ログイン画面へ
                    </Button>
                </div>
            </StepLayout>
        );
    }

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
        <StepLayout title="登録内容の確認" description="入力内容を確認してください" onBack={onBack}>
            <div className="space-y-6">
                <div className="bg-gray-50 rounded-lg p-6 space-y-4">
                    <div className="flex items-center space-x-2 text-xl">
                        {/* <CheckCircleIcon className="h-6 w-6 text-green-500" /> */}
                        {registrationData.preview && (
                            <Image
                                src={registrationData.preview}
                                alt="Profile Preview"
                                width={64}
                                height={64}
                            />
                        )}
                        {registrationData.profile?.last_name} {registrationData.profile?.first_name}
                    </div>
                    <div className="grid grid-cols-1 gap-4">
                        <div>
                            <h3 className="text-sm font-medium text-gray-500">基本情報</h3>
                            <p className="text-sm">メールアドレス: {registrationData.email}</p>
                            <p className="text-sm">認証方法: {registrationData.authMethod}</p>
                        </div>

                        <div>
                            <h3 className="text-sm font-medium text-gray-500">プロフィール</h3>
                            <p className="text-sm">
                                氏名: {registrationData.profile?.last_name} {registrationData.profile?.first_name}
                            </p>
                            <p className="text-sm">電話番号: {registrationData.profile?.phone}</p>
                            <p className="text-sm">
                                生年月日:{' '}
                                {registrationData.profile?.dateOfBirth &&
                                    new Date(registrationData.profile.dateOfBirth).toLocaleDateString()}
                            </p>
                            {registrationData.profile?.department && (
                                <p className="text-sm">部署: {registrationData.profile.department}</p>
                            )}
                        </div>

                        <div>
                            <h3 className="text-sm font-medium text-gray-500">住所</h3>
                            <p className="text-sm">
                                〒{registrationData.profile?.address?.zip}{' '}
                                {registrationData.profile?.address?.state}{' '}
                                {registrationData.profile?.address?.city}
                            </p>
                            <p className="text-sm">
                                {registrationData.profile?.address?.street}{' '}
                                {registrationData.profile?.address?.street2}
                            </p>
                            <p className="text-sm">{registrationData.profile?.address?.country}</p>
                        </div>

                        {/* <div>
                            <h3 className="text-sm font-medium text-gray-500">パスワード</h3>
                            <p className="text-sm">パスワード: {registrationData.password}</p>
                            <p className="text-sm">パスワード（確認）: {registrationData.confirmPassword}</p>
                        </div> */}
                    </div>
                    {registrationData.preview && (
                        <div>
                            <h3 className="text-sm font-medium text-gray-500">プロフィール画像</h3>
                            <img
                                src={registrationData.preview}
                                alt="Profile Preview"
                                className="mt-2 h-24 w-24 object-cover rounded-full border"
                            />
                        </div>
                    )}
                </div>

                <div className="flex justify-between">
                    <Button variant="ghost" onClick={onBack} disabled={isSubmitting}>
                        戻る
                    </Button>
                    <Button onClick={handleSubmit} disabled={isSubmitting} className="min-w-[120px]">
                        {isSubmitting ? '登録中...' : '登録'}
                    </Button>
                </div>
            </div>
        </StepLayout>
    );
}