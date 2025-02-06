import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { PasskeyDialog } from './PasskeyDialog';
import { usePasskey } from '@/app/hooks/usePasskey';

export const PasskeyButton: React.FC = () => {
    const [isDialogOpen, setIsDialogOpen] = useState(false);
    const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
    const [statusMessage, setStatusMessage] = useState('パスキーを使用してログイン');
    const { initiatePasskeyLogin, isLoading, error } = usePasskey();

    const handlePasskeyLogin = async () => {
        setIsDialogOpen(true);
        setStatus('loading');
        setStatusMessage('認証中...');

        try {
            await initiatePasskeyLogin();
            setStatus('success');
            setStatusMessage('認証成功');

            // Close dialog and redirect after short delay
            setTimeout(() => {
                setIsDialogOpen(false);
            }, 1500);
        } catch (err) {
            setStatus('error');
            setStatusMessage(error || '認証に失敗しました');

            // Reset to idle state after error
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
                className="w-full bg-gray-100 hover:bg-gray-200 text-gray-600 transition-colors"
                disabled={isLoading}
            >
                パスキーでログイン
            </Button>

            <PasskeyDialog
                isOpen={isDialogOpen}
                onClose={() => {
                    if (status !== 'loading') {
                        setIsDialogOpen(false);
                        setStatus('idle');
                        setStatusMessage('パスキーを使用してログイン');
                    }
                }}
                status={status}
                statusMessage={statusMessage}
            />
        </>
    );
};