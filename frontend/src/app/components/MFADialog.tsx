// components/MFADialog.tsx
import React, { useState } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter
} from '@/app/components/ui/dialog';

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
                    <input
                        type="text"
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        placeholder="000000"
                        pattern="[0-9]*"
                        maxLength={6}
                        autoComplete="one-time-code"
                        required
                        disabled={isLoading}
                    />
                </DialogContent>

                <DialogFooter>
                    <button
                        type="button"
                        onClick={onClose}
                        className="inline-flex justify-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        disabled={isLoading}
                    >
                        キャンセル
                    </button>
                    <button
                        type="submit"
                        className="inline-flex justify-center px-4 py-2 text-sm font-medium text-white bg-blue-500 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                        disabled={isLoading}
                    >
                        {isLoading ? '確認中...' : '確認'}
                    </button>
                </DialogFooter>
            </form>
        </Dialog>
    );
};

export default MFADialog;