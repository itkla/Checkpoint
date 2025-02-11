import React from 'react';
import { XCircleIcon } from '@heroicons/react/24/solid';
import { KeyIcon, CheckIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { Button } from '@/components/ui/button';

interface PasskeyDialogProps {
    isOpen: boolean;
    onClose: () => void;
    status: 'idle' | 'loading' | 'success' | 'error';
    statusMessage: string;
}

export const PasskeyDialog: React.FC<PasskeyDialogProps> = ({
    isOpen,
    onClose,
    status,
    statusMessage,
}) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 flex items-center justify-center bg-black/50">
            <div className="bg-white rounded-lg w-80 h-80 relative flex flex-col items-center justify-center">
                <button
                    onClick={onClose}
                    className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
                >
                    <XCircleIcon className="w-6 h-6" />
                </button>

                <div className="flex flex-col items-center justify-center space-y-6">
                    {status === 'loading' ? (
                        <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500" />
                    ) : status === 'success' ? (
                        <CheckIcon className="w-16 h-16 text-green-500" />
                    ) : status === 'error' ? (
                        <XMarkIcon className="w-16 h-16 text-red-500" />
                    ) : (
                        <KeyIcon className="w-16 h-16 text-blue-500" />
                    )}

                    <p className={`text-2xl text-center ${status === 'error' ? 'text-red-600' : 'text-gray-800'
                        }`}>
                        {statusMessage}
                    </p>

                    {status === 'error' && (
                        <Button
                            variant="outline"
                            onClick={onClose}
                            className="mt-4"
                        >
                            閉じる
                        </Button>
                    )}
                </div>
            </div>
        </div>
    );
};