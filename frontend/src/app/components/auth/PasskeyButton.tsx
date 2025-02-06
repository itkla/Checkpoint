import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { startAuthentication } from '@simplewebauthn/browser';
import { Button } from '@/components/ui/button';
import { PasskeyDialog } from './PasskeyDialog';
import { authApi } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';

interface PasskeyButtonProps {
    email: string;
}

export function PasskeyButton({ email }: PasskeyButtonProps) {
    const [isDialogOpen, setIsDialogOpen] = useState(false);
    const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
    const [statusMessage, setStatusMessage] = useState('パスキーを使用してログイン');
    const router = useRouter();
    const { toast } = useToast();

    const handlePasskeyLogin = async () => {
        if (!email) {
            toast({
                title: "エラー",
                description: "メールアドレスを入力してください",
                variant: "destructive",
            });
            return;
        }

        setIsDialogOpen(true);
        setStatus('loading');
        setStatusMessage('パスキーを準備中...');

        try {
            const options = await authApi.initiatePasskey(email);
            setStatusMessage('パスキーを使用して認証してください');

            const credential = await startAuthentication(options);
            setStatusMessage('認証を確認中...');

            const response = await authApi.completePasskey(email, credential);

            if (response.token) {
                setStatus('success');
                setStatusMessage('認証成功！');
                localStorage.setItem('token', response.token);

                setTimeout(() => {
                    router.push('/dashboard');
                }, 1500);
            } else {
                throw new Error('認証に失敗しました');
            }
        } catch (err) {
            console.error('Passkey authentication error:', err);
            setStatus('error');
            setStatusMessage(err instanceof Error ? err.message : '認証に失敗しました');

            setTimeout(() => {
                setStatus('idle');
                setStatusMessage('パスキーを使用してログイン');
            }, 2000);
        }
    };

    return (
        <>
            <Button
                onClick={handlePasskeyLogin}
                variant="secondary"
                className="w-full text-gray-600"
                disabled={status === 'loading'}
            >
                パスキーでログイン
            </Button>

            <PasskeyDialog
                isOpen={isDialogOpen}
                onClose={() => status !== 'loading' && setIsDialogOpen(false)}
                status={status}
                statusMessage={statusMessage}
            />
        </>
    );
}