import { useState } from 'react';

interface PasskeyRegistrationProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => void;
}
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { registerPasskey } from '@/lib/webauthn';
import { FingerPrintIcon } from '@heroicons/react/24/outline';

export function PasskeyRegistration({
    open,
    onOpenChange,
    onSuccess,
}: PasskeyRegistrationProps) {
    const [name, setName] = useState('');
    const [isRegistering, setIsRegistering] = useState(false);
    const { toast } = useToast();

    const handleRegistration = async () => {
        if (!name) return;

        setIsRegistering(true);
        try {
            // Check if browser supports WebAuthn
            if (!window.PublicKeyCredential) {
                throw new Error('このブラウザはパスキーをサポートしていません');
            }

            // Check if device supports platform authenticator
            const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            if (!available) {
                throw new Error('このデバイスはパスキーをサポートしていません');
            }

            await registerPasskey(name);
            toast({
                title: "成功",
                description: "パスキーを登録しました",
            });
            onSuccess();
            onOpenChange(false);
        } catch (error: any) {
            console.error('Registration error:', error);
            toast({
                title: "エラー",
                description: error.message || "パスキーの登録に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsRegistering(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle>パスキーの登録</DialogTitle>
                    <DialogDescription>
                        生体認証やデバイスのセキュリティ機能を使用してログインできます
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="passkey-name">パスキーの名前</Label>
                        <Input
                            id="passkey-name"
                            placeholder="例: MacBook Pro の Touch ID"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>

                    <div className="flex justify-end space-x-2">
                        <Button
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                            disabled={isRegistering}
                        >
                            キャンセル
                        </Button>
                        <Button
                            onClick={handleRegistration}
                            disabled={isRegistering}
                        >
                            {isRegistering ? '登録中...' : 'パスキーを登録'}
                        </Button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
}