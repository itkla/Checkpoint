import React, { useState } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter
} from '@/app/components/ui/dialog';

import {
    InputOTP,
    InputOTPGroup,
    InputOTPSeparator,
    InputOTPSlot,
} from "@/components/ui/input-otp"

import { Button } from '@/components/ui/button';

interface MFADialogProps {
    isOpen: boolean;
    onSubmit: (code: string) => void;
    onClose: () => void;
}

export const MFADialog: React.FC<MFADialogProps> = ({
    isOpen,
    onSubmit,
    onClose
}) => {
    const [code, setCode] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        await onSubmit(code);
        setIsLoading(false);
    };

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <form onSubmit={handleSubmit}>
                <DialogHeader>
                    <DialogTitle>2段階認証</DialogTitle>
                </DialogHeader>

                <DialogContent>
                    <p className="text-sm text-gray-500 mb-4">
                        認証アプリで生成された6桁のコードを入力してください。
                    </p>
                    <div className="mt-1 items-center justify-center flex">
                        <InputOTP 
                            maxLength={6} 
                            value={code} 
                            onChange={setCode} 
                            disabled={isLoading}
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
                    </div>
                </DialogContent>

                <DialogFooter>
                    <Button
                        type="button"
                        onClick={onClose}
                        className="inline-flex justify-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        disabled={isLoading}
                    >
                        キャンセル
                    </Button>
                    <Button
                        type="submit"
                        className="inline-flex justify-center px-4 py-2 text-sm font-medium text-white border border-transparent rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        disabled={isLoading}
                    >
                        {isLoading ? '確認中...' : '確認'}
                    </Button>
                </DialogFooter>
            </form>
        </Dialog>
    );
};

export default MFADialog;