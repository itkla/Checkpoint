'use client';

import { useState } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { QRCodeSVG as QRCode } from 'qrcode.react';
import { api } from '@/lib/api-client';
import MFADialog from '../MFADialog';

interface TwoFactorSetupProps {
    isOpen: boolean;
    onClose: () => void;
    onComplete: () => void;
    is2FAEnabled: boolean;
    // remove2FA: () => void;
}

export function TwoFactorSetup({ isOpen, onClose, onComplete, is2FAEnabled }: TwoFactorSetupProps) {
    // const [secret, setSecret] = useState('');
    const [otpauth, setOtpauth] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [code, setCode] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [isLoadingSetup, setIsLoadingSetup] = useState(false);
    const [showMFADialog, setShowMFADialog] = useState(false);
    const { toast } = useToast();

    // get current user
    // const user

    const initSetup = async () => {
        setIsLoadingSetup(true);
        try {
            const response = await api.auth.initiate2FA();
            // setSecret(response.secret);
            setOtpauth(response.otpauth);
            setQrCode(response.qrCodeDataURL);
        } catch (error: any) {
            toast({
                title: "エラー",
                description: "2要素認証の設定開始に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoadingSetup(false);
        }
    };

    const verifyCode = async () => {
        setIsVerifying(true);
        try {
            await api.auth.verify2FA(code);
            toast({
                title: "成功",
                description: "2要素認証が正常に設定されました",
            });
            onComplete();
            onClose();
        } catch (error: any) {
            if (error.statusCode === 400) {
                toast({
                    title: "エラー",
                    description: "認証コードが正しくありません",
                    variant: "destructive",
                });
            } else {
                toast({
                    title: "エラー",
                    description: "An error has occurred: " + error,
                    variant: "destructive",
                });
            }
            
        } finally {
            setIsVerifying(false);
        }
    };

    const remove2FA = async () => {
        setIsLoadingSetup(true);
        try {
            
            await api.auth.disable2FA(code);
            toast({
                title: "成功",
                description: "2要素認証が正常に解除されました",
            });
            onComplete();
            onClose();
        } catch (error: any) {
            toast({
                title: "エラー",
                description: "2要素認証の解除に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoadingSetup(false);
        }
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-md">
                <DialogHeader>
                    <DialogTitle className="text-left">2段階認証の設定</DialogTitle>
                </DialogHeader>

                <div className="space-y-6">
                    {qrCode ? (
                            <>
                                <div className="flex justify-center">
                                    <div className="w-48 h-48 bg-white rounded shadow">
                                        <QRCode value={otpauth} size={200} />
                                    </div>
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
                                    autoComplete="one-time-code"
                                />
                                <Button onClick={verifyCode} className="w-full" disabled={isVerifying}>
                                    {isVerifying ? '確認中...' : '確認'}
                                </Button>
                            </>
                        ) : (
                            is2FAEnabled ? (
                                <>
                                    <Button onClick={() => setShowMFADialog(true)} className="w-1/3" disabled={isLoadingSetup}>
                                        {isLoadingSetup ? '解除処理中...' : '2FAを解除'}
                                    </Button>
                                    <MFADialog
                                        isOpen={showMFADialog}
                                        onClose={() => setShowMFADialog(false)}
                                        onSubmit={(otpCode: string) => {
                                            setCode(otpCode);
                                            remove2FA();
                                            setShowMFADialog(false);
                                        }}
                                    />
                                </>
                            ) : (
                                <Button onClick={initSetup} className="w-1/3" disabled={isLoadingSetup}>
                                    {isLoadingSetup ? '設定準備中...' : '設定を開始'}
                                </Button>
                            )
                        )}
                </div>

                <DialogFooter>
                    <Button variant="outline" onClick={onClose} disabled={isLoadingSetup || isVerifying}>
                        キャンセル
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

export default TwoFactorSetup;
