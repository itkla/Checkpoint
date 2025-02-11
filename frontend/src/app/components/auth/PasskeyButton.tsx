import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { PasskeyDialog } from './PasskeyDialog';
import { useToast } from '@/hooks/use-toast';
import { loginWithPasskey } from '@/lib/webauthn';

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
            setStatusMessage('パスキーを使用して認証してください');
            const result = await loginWithPasskey(email);

            if (result.success && result.token) {
                localStorage.setItem('token', result.token);
                setStatus('success');
                setStatusMessage('認証成功！');

                setTimeout(() => {
                    router.push('/dashboard');
                }, 1500);
            }
        } catch (error: any) {
            setStatus('error');
            setStatusMessage('認証に失敗しました');

            toast({
                title: "エラー",
                description: error.message || "パスキー認証に失敗しました",
                variant: "destructive",
            });

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