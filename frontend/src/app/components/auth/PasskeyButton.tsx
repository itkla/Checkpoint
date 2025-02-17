import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { PasskeyDialog } from './PasskeyDialog';
import { useToast } from '@/hooks/use-toast';
import { loginWithPasskey } from '@/lib/webauthn';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline';

interface PasskeyButtonProps {
    email: string;
}

export function PasskeyButton({ email }: PasskeyButtonProps) {
    const [isDialogOpen, setIsDialogOpen] = useState(false);
    const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
    const [statusMessage, setStatusMessage] = useState<React.ReactNode>('パスキーでログイン');
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

        setStatus('loading');
        setStatusMessage('パスキーを準備中...');

        try {
            setStatusMessage('パスキーを使用して認証してください');
            const result = await loginWithPasskey(email);

            if (result.success && result.token) {
                localStorage.setItem('token', result.token);
                setStatus('success');
                setStatusMessage(<CheckCircleIcon className="w-5 h-5" />);
                // setIsDialogOpen(true);
                setTimeout(() => {
                    router.push('/me');
                }, 1500);
            }
        } catch (error: any) {
            setStatus('error');
            setStatusMessage(<XCircleIcon className="w-5 h-5" />);

            toast({
                title: "エラー",
                description: error.message || "パスキー認証に失敗しました",
                variant: "destructive",
            });

            setTimeout(() => {
                setStatus('idle');
                setStatusMessage('パスキーでログイン');
            }, 2000);
        }
    };

    return (
        <>
            <Button
                onClick={handlePasskeyLogin}
                variant="secondary"
                className={`w-full text-gray-600 ${status === 'success' ? 'bg-green-500 text-white hover:bg-green-600' : status === 'error' ? 'bg-red-500 text-white hover:bg-red-600' : ''}`}
                disabled={status === 'loading'}
            >
                {status === 'loading' ? (
                    <svg className="animate-spin h-5 w-5 text-gray-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                    </svg>
                ) : (
                    statusMessage
                )}
            </Button>
        </>
    );
}