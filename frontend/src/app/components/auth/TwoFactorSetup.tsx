import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { QRCodeSVG as QRCode } from 'qrcode.react';
import { api } from '@/lib/api-client';

interface TwoFactorSetupProps {
    isOpen: boolean;
    onClose: () => void;
    onComplete: () => void;
}

export function TwoFactorSetup({ isOpen, onClose, onComplete }: TwoFactorSetupProps) {
    const [secret, setSecret] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [code, setCode] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const { toast } = useToast();

    const initSetup = async () => {
        try {
            const response = await api.auth.initiate2FA();
            setSecret(response.secret);
            setQrCode(response.qrCode);
        } catch (error) {
            toast({
                title: "エラー",
                description: "2要素認証の設定開始に失敗しました",
                variant: "destructive",
            });
        }
    };

    const verifyCode = async () => {
        setIsVerifying(true);
        try {
            await api.auth.verify2FA({ secret, code });
            toast({
                title: "成功",
                description: "2要素認証が正常に設定されました",
            });
            onComplete();
        } catch (error) {
            toast({
                title: "エラー",
                description: "認証コードが正しくありません",
                variant: "destructive",
            });
        } finally {
            setIsVerifying(false);
        }
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>2要素認証の設定</DialogTitle>
                </DialogHeader>

                <div className="space-y-4">
                    {qrCode ? (
                        <>
                            <div className="flex justify-center">
                                <QRCode value={qrCode} size={200} />
                            </div>
                            <p className="text-sm text-gray-600 text-center">
                                認証アプリでQRコードをスキャンし、表示された6桁のコードを入力してください
                            </p>
                            <Input
                                type="text"
                                placeholder="000000"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                maxLength={6}
                                className="text-center text-2xl"
                            />
                            <Button
                                onClick={verifyCode}
                                className="w-full"
                                disabled={isVerifying}
                            >
                                {isVerifying ? '確認中...' : '確認'}
                            </Button>
                        </>
                    ) : (
                        <Button onClick={initSetup} className="w-full">
                            設定を開始
                        </Button>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}