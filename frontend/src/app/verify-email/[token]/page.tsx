'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline';
import { Button } from '@/components/ui/button';

export default function VerifyEmailPage({
    params: { token },
}: {
    params: { token: string };
}) {
    const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying');
    const router = useRouter();
    const { toast } = useToast();

    useEffect(() => {
        const verifyEmail = async () => {
            try {
                await api.auth.verifyEmail(token);
                setStatus('success');
                toast({
                    title: "メール認証完了",
                    description: "メールアドレスの確認が完了しました",
                });
            } catch (error) {
                setStatus('error');
                toast({
                    title: "エラー",
                    description: "メールアドレスの確認に失敗しました",
                    variant: "destructive",
                });
            }
        };

        verifyEmail();
    }, [token, toast]);

    return (
        <div className="container flex justify-center items-center min-h-screen">
            <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-[5%]">
                <div className="text-center">
                    {status === 'verifying' && (
                        <>
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto" />
                            <h2 className="mt-4 text-2xl font-bold">メールアドレスを確認中</h2>
                            <p className="mt-2 text-gray-600">
                                しばらくお待ちください...
                            </p>
                        </>
                    )}

                    {status === 'success' && (
                        <>
                            <CheckCircleIcon className="mx-auto h-12 w-12 text-green-500" />
                            <h2 className="mt-4 text-2xl font-bold">確認完了</h2>
                            <p className="mt-2 text-gray-600">
                                メールアドレスの確認が完了しました
                            </p>
                            <Button
                                className="mt-6"
                                onClick={() => router.push('/login')}
                            >
                                ログインする
                            </Button>
                        </>
                    )}

                    {status === 'error' && (
                        <>
                            <XCircleIcon className="mx-auto h-12 w-12 text-red-500" />
                            <h2 className="mt-4 text-2xl font-bold">確認エラー</h2>
                            <p className="mt-2 text-gray-600">
                                メールアドレスの確認に失敗しました。
                                リンクが無効か期限切れの可能性があります。
                            </p>
                            <div className="mt-6 space-x-4">
                                <Button
                                    variant="outline"
                                    onClick={() => router.push('/register')}
                                >
                                    新規登録
                                </Button>
                                <Button onClick={() => router.push('/login')}>
                                    ログイン
                                </Button>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}