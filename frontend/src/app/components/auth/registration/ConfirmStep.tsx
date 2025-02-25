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

    async function uploadProfilePicture(userId: string, file: File) {
        const response = await api.users.uploadProfilePicture(file, userId);
        return response;
    }
    console.log(registrationData);

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
                <div className="flex flex-col items-center justify-center text-center p-4">
                    {registrationData.preview ? (
                        <div className="relative mb-3">
                            <img
                                src={registrationData.preview}
                                alt="プロフィール画像"
                                className="h-24 w-24 object-cover rounded-full border-2 border-gray-100 shadow-sm"
                            />
                            <div className="absolute -bottom-1 -right-1 bg-green-500 text-white rounded-full p-1">
                                <CheckCircleIcon className="h-5 w-5" />
                            </div>
                        </div>
                    ) : (
                        <div className="h-24 w-24 bg-gray-200 rounded-full flex items-center justify-center mb-3">
                            <span className="text-gray-500 text-2xl">
                                {registrationData.profile?.first_name?.[0] || ''}
                                {registrationData.profile?.last_name?.[0] || ''}
                            </span>
                        </div>
                    )}
                    <h2 className="text-xl font-medium">
                        {registrationData.profile?.last_name} {registrationData.profile?.first_name}
                    </h2>
                    <p className="text-gray-500 text-sm">{registrationData.email}</p>
                </div>
                <div className="divide-y divide-gray-100 border border-gray-100 rounded-lg overflow-hidden">
                    <div className="bg-white p-4">
                        <h3 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            基本情報
                        </h3>
                        <dl className="grid grid-cols-1 gap-2 text-sm">
                            <div className="flex justify-between py-1">
                                <dt className="text-gray-500">メールアドレス</dt>
                                <dd className="text-gray-900 font-medium">{registrationData.email}</dd>
                            </div>
                            <div className="flex justify-between py-1">
                                <dt className="text-gray-500">認証方法</dt>
                                <dd className="text-gray-900 font-medium">{registrationData.authMethod === 'password' ? 'パスワード' : registrationData.authMethod}</dd>
                            </div>
                        </dl>
                    </div>
                    <div className="bg-white p-4">
                        <h3 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                            </svg>
                            プロフィール
                        </h3>
                        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-sm">
                            <div className="flex justify-between py-1">
                                <dt className="text-gray-500">氏名</dt>
                                <dd className="text-gray-900 font-medium">
                                    {registrationData.profile?.last_name} {registrationData.profile?.first_name}
                                </dd>
                            </div>
                            <div className="flex justify-between py-1">
                                <dt className="text-gray-500">電話番号</dt>
                                <dd className="text-gray-900 font-medium">{registrationData.profile?.phone}</dd>
                            </div>
                            <div className="flex justify-between py-1">
                                <dt className="text-gray-500">生年月日</dt>
                                <dd className="text-gray-900 font-medium">
                                    {registrationData.profile?.dateOfBirth &&
                                        new Date(registrationData.profile.dateOfBirth).toLocaleDateString('ja-JP', {
                                            year: 'numeric',
                                            month: 'long',
                                            day: 'numeric'
                                        })}
                                </dd>
                            </div>
                            {registrationData.profile?.department && (
                                <div className="flex justify-between py-1">
                                    <dt className="text-gray-500">部署</dt>
                                    <dd className="text-gray-900 font-medium">{registrationData.profile.department}</dd>
                                </div>
                            )}
                        </dl>
                    </div>
                    <div className="bg-white p-4">
                        <h3 className="text-sm font-medium text-gray-900 mb-3 flex items-center">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                            </svg>
                            住所
                        </h3>
                        <div className="bg-gray-50 rounded-md p-3 text-sm">
                            <p className="font-medium">
                                〒{registrationData.profile?.address?.zip}
                            </p>
                            <p className="mt-1">
                                {registrationData.profile?.address?.state} {registrationData.profile?.address?.city}
                            </p>
                            <p className="mt-1">
                                {registrationData.profile?.address?.street} {registrationData.profile?.address?.street2 || ''}
                            </p>
                            <p className="mt-1 text-gray-500">
                                {registrationData.profile?.address?.country}
                            </p>
                        </div>
                    </div>
                </div>

                <div className="flex justify-between pt-4">
                    <Button variant="ghost" onClick={onBack} disabled={isSubmitting}>
                        戻る
                    </Button>
                    <Button
                        onClick={handleSubmit}
                        disabled={isSubmitting}
                        className="min-w-[120px]"
                    >
                        {isSubmitting ? '登録中...' : '登録完了'}
                    </Button>
                </div>
            </div>
        </StepLayout>
    );
}