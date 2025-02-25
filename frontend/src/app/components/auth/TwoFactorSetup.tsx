'use client';

import { useState } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
    DialogDescription
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { QRCodeSVG as QRCode } from 'qrcode.react';
import { api } from '@/lib/api-client';
import MFADialog from '../MFADialog';

import {
    InputOTP,
    InputOTPGroup,
    InputOTPSlot,
} from "@/components/ui/input-otp";

import {
    ShieldCheckIcon,
    ShieldExclamationIcon,
    QrCodeIcon,
    KeyIcon,
    XMarkIcon,
    ArrowPathIcon,
    CheckIcon,
    ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

interface TwoFactorSetupProps {
    isOpen: boolean;
    onClose: () => void;
    onComplete: () => void;
    is2FAEnabled: boolean;
}

export function TwoFactorSetup({ isOpen, onClose, onComplete, is2FAEnabled }: TwoFactorSetupProps) {
    const [otpauth, setOtpauth] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [code, setCode] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
    const [isLoadingSetup, setIsLoadingSetup] = useState(false);
    const [showMFADialog, setShowMFADialog] = useState(false);
    const [hasShownRecoveryDialog, setHasShownRecoveryDialog] = useState(false);
    const [showRecoveryDialog, setShowRecoveryDialog] = useState(false);
    const { toast } = useToast();

    const initSetup = async () => {
        try {
            setIsLoadingSetup(true);
            const response = await api.auth.initiate2FA();
            setQrCode(response.qrCodeDataURL);
            setOtpauth(response.otpauth);
            setRecoveryCodes(response.recovery_codes);
        } catch (error: any) {
            toast({
                title: "エラー",
                description: "2要素認証の設定開始に失敗しました",
                variant: "destructive",
                icon: <ExclamationTriangleIcon className="h-5 w-5" />
            });
        } finally {
            setIsLoadingSetup(false);
        }
    };

    const verifyCode = async () => {
        setIsVerifying(true);
        try {
            await api.auth.verify2FA(code);
            
            if (!hasShownRecoveryDialog) {
                setHasShownRecoveryDialog(true);
                setShowRecoveryDialog(true);
            }
        } catch (error: any) {
            if (error.statusCode === 400) {
                toast({
                    title: "エラー",
                    description: "認証コードが正しくありません",
                    variant: "destructive",
                    icon: <ExclamationTriangleIcon className="h-5 w-5" />
                });
            } else {
                toast({
                    title: "エラー",
                    description: `An error has occurred: ${error}`,
                    variant: "destructive",
                    icon: <ExclamationTriangleIcon className="h-5 w-5" />
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
                icon: <CheckIcon className="h-5 w-5 text-green-500" />
            });
            onComplete();
            onClose();
        } catch (error: any) {
            toast({
                title: "エラー",
                description: "2要素認証の解除に失敗しました",
                variant: "destructive",
                icon: <ExclamationTriangleIcon className="h-5 w-5" />
            });
        } finally {
            setIsLoadingSetup(false);
        }
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-md">
                <DialogHeader className="flex flex-row items-center gap-2">
                    {is2FAEnabled ? 
                        <ShieldCheckIcon className="h-6 w-6 text-green-500" /> : 
                        <ShieldExclamationIcon className="h-6 w-6 text-amber-500" />
                    }
                    <DialogTitle>2段階認証の設定</DialogTitle>
                </DialogHeader>

                <div className="space-y-6 py-2">
                    {qrCode ? (
                        <div className="flex flex-col items-center space-y-4">
                            <div className="flex justify-center">
                                <div className="w-52 h-52 bg-white rounded-lg shadow-md p-1 border">
                                    <QRCode value={otpauth} size={200} />
                                </div>
                            </div>
                            <div className="flex items-center gap-2 text-sm text-gray-600 text-center">
                                <QrCodeIcon className="h-5 w-5 text-gray-500" />
                                <p>認証アプリでQRコードをスキャンし、表示された6桁のコードを入力してください</p>
                            </div>
                            <InputOTP
                                value={code}
                                onChange={setCode}
                                maxLength={6}
                                autoComplete="one-time-code"
                                className="flex justify-center"
                            >
                                <InputOTPGroup>
                                    <InputOTPSlot index={0} />
                                    <InputOTPSlot index={1} />
                                    <InputOTPSlot index={2} />
                                    <InputOTPSlot index={3} />
                                    <InputOTPSlot index={4} />
                                    <InputOTPSlot index={5} />
                                </InputOTPGroup>
                            </InputOTP>
                            <Button 
                                onClick={verifyCode} 
                                className="w-full" 
                                disabled={isVerifying}
                            >
                                {isVerifying ? (
                                    <>
                                        <ArrowPathIcon className="h-4 w-4 mr-2 animate-spin" />
                                        確認中...
                                    </>
                                ) : (
                                    <>
                                        <CheckIcon className="h-4 w-4 mr-2" />
                                        確認
                                    </>
                                )}
                            </Button>
                        </div>
                    ) : (
                        is2FAEnabled ? (
                            <div className="flex flex-col items-center space-y-4">
                                <div className="flex items-center justify-center bg-amber-50 p-4 rounded-lg border border-amber-200">
                                    <ShieldExclamationIcon className="h-8 w-8 text-amber-500 mr-3" />
                                    <p className="text-sm text-amber-800">
                                        現在2段階認証が有効です。解除するには認証コードが必要です。
                                    </p>
                                </div>
                                <Button 
                                    onClick={() => setShowMFADialog(true)} 
                                    className="w-full" 
                                    variant="destructive"
                                    disabled={isLoadingSetup}
                                >
                                    {isLoadingSetup ? (
                                        <>
                                            <ArrowPathIcon className="h-4 w-4 mr-2 animate-spin" />
                                            解除処理中...
                                        </>
                                    ) : (
                                        <>
                                            <ShieldExclamationIcon className="h-4 w-4 mr-2" />
                                            2FAを解除
                                        </>
                                    )}
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
                            </div>
                        ) : (
                            <div className="flex flex-col items-center space-y-4">
                                <div className="flex items-center justify-center bg-blue-50 p-4 rounded-lg border border-blue-200">
                                    <ShieldCheckIcon className="h-8 w-8 text-blue-500 mr-3" />
                                    <p className="text-sm text-blue-800">
                                        2段階認証を設定すると、アカウントのセキュリティが強化されます。
                                    </p>
                                </div>
                                <Button 
                                    onClick={initSetup} 
                                    className="w-full" 
                                    disabled={isLoadingSetup}
                                >
                                    {isLoadingSetup ? (
                                        <>
                                            <ArrowPathIcon className="h-4 w-4 mr-2 animate-spin" />
                                            設定準備中...
                                        </>
                                    ) : (
                                        <>
                                            <ShieldCheckIcon className="h-4 w-4 mr-2" />
                                            設定を開始
                                        </>
                                    )}
                                </Button>
                            </div>
                        )
                    )}
                </div>

                <Dialog open={showRecoveryDialog} onOpenChange={() => setShowRecoveryDialog(false)}>
                    <DialogContent className="max-w-md">
                        <DialogHeader className="flex flex-row items-center gap-2">
                            <KeyIcon className="h-6 w-6 text-amber-500" />
                            <DialogTitle>リカバリーコード</DialogTitle>
                        </DialogHeader>
                        <DialogDescription>
                            以下のコードを安全な場所に保存してください
                        </DialogDescription>
                        
                        <div className="space-y-4">
                            <p className="text-sm text-gray-600">
                                以下のリカバリーコードを安全な場所に保存してください。2要素認証デバイスにアクセスできなくなった場合に、これらのコードを使用してアカウントにログインできます。
                            </p>
                            <div className="bg-gray-100 p-4 rounded-md border">
                                <ul className="grid grid-cols-2 gap-2">
                                    {recoveryCodes.map((code, index) => (
                                        <li key={index} className="font-mono text-center bg-white p-2 rounded border text-sm">
                                            {code}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                            <div className="flex items-center bg-red-50 p-3 rounded-md border border-red-200">
                                <ExclamationTriangleIcon className="h-5 w-5 text-red-500 mr-2 flex-shrink-0" />
                                <p className="text-sm text-red-600">
                                    これらのコードは再度表示されませんので、必ず保存してください。
                                </p>
                            </div>
                        </div>
                        <DialogFooter>
                            <Button 
                                onClick={() => {
                                    setShowRecoveryDialog(false);
                                    toast({
                                        title: "成功",
                                        description: "2要素認証が正常に設定されました",
                                        icon: <CheckIcon className="h-5 w-5 text-green-500" />
                                    });
                                    onComplete();
                                    onClose();
                                }}
                                className="w-full sm:w-auto"
                            >
                                <CheckIcon className="h-4 w-4 mr-2" />
                                コードを保存しました
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                </Dialog>
                
                <DialogFooter>
                    <Button 
                        variant="outline" 
                        onClick={onClose} 
                        disabled={isLoadingSetup || isVerifying}
                        className="w-full sm:w-auto"
                    >
                        <XMarkIcon className="h-4 w-4 mr-2" />
                        キャンセル
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

export default TwoFactorSetup;