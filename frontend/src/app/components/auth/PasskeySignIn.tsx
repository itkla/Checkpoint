import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { signInWithPasskey } from '@/lib/webauthn';
import { KeyIcon } from '@heroicons/react/24/outline';

interface PasskeySignInProps {
    email: string;
}

export function PasskeySignIn({ email }: PasskeySignInProps) {
    const [isAuthenticating, setIsAuthenticating] = useState(false);
    const router = useRouter();
    const { toast } = useToast();

    const handlePasskeySignIn = async () => {
        if (!email) {
            toast({
                title: "エラー",
                description: "メールアドレスを入力してください",
                variant: "destructive",
            });
            return;
        }

        setIsAuthenticating(true);
        try {
            const response = await signInWithPasskey(email);

            if (response.token) {
                localStorage.setItem('token', response.token);
                router.push('/dashboard');
            } else {
                throw new Error('認証に失敗しました');
            }
        } catch (error: any) {
            toast({
                title: "エラー",
                description: error.message || "パスキーでのログインに失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsAuthenticating(false);
        }
    };

    return (
        <Button
            variant="outline"
            className="w-full flex items-center justify-center space-x-2"
            onClick={handlePasskeySignIn}
            disabled={isAuthenticating || !email}
        >
            <KeyIcon className="w-5 h-5" />
            <span>
                {isAuthenticating ? 'パスキーで認証中...' : 'パスキーでログイン'}
            </span>
        </Button>
    );
}