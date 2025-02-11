import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';
import { FingerPrintIcon, TrashIcon, PlusIcon } from '@heroicons/react/24/outline';
import { PasskeyRegistration } from './PasskeyRegistration';
import { exportCredential, importCredential } from '@/lib/webauthn';

interface Passkey {
    id: string;
    credentialId: string;
    name: string;
    createdAt: string;
    lastUsed?: string;
}

export function PasskeyManager({ open, onOpenChange }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const [passkeys, setPasskeys] = useState<Passkey[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [showRegistration, setShowRegistration] = useState(false);
    const { toast } = useToast();

    const fetchPasskeys = async () => {
        try {
            const response = await api.auth.getPasskeys();
            // Ensure we always have an array, even if empty
            setPasskeys(Array.isArray(response) ? response : []);
        } catch (error) {
            console.error('Error fetching passkeys:', error);
            toast({
                title: "エラー",
                description: "パスキーの取得に失敗しました",
                variant: "destructive",
            });
            setPasskeys([]); // Set empty array on error
        } finally {
            setIsLoading(false);
        }
    };

    const deletePasskey = async (credentialId: string) => {
        try {
            await api.auth.deletePasskey(credentialId);
            setPasskeys(prev => prev.filter(p => p.credentialId !== credentialId));
            toast({
                title: "成功",
                description: "パスキーを削除しました",
            });
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスキーの削除に失敗しました",
                variant: "destructive",
            });
        }
    };

    const handleExport = async (credentialId: string) => {
        try {
            const exportedKey = await exportCredential(credentialId);
            // Create and download a JSON file
            const blob = new Blob([JSON.stringify(exportedKey)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'passkey-backup.json';
            a.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスキーのエクスポートに失敗しました",
                variant: "destructive",
            });
        }
    };

    const handleImport = async () => {
        try {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'application/json';
            input.onchange = async (e) => {
                const file = (e.target as HTMLInputElement).files?.[0];
                if (!file) return;

                const reader = new FileReader();
                reader.onload = async (e) => {
                    const credentialData = JSON.parse(e.target?.result as string);
                    await importCredential(credentialData);
                    fetchPasskeys(); // Refresh the list
                    toast({
                        title: "成功",
                        description: "パスキーを輸入しました",
                    });
                };
                reader.readAsText(file);
            };
            input.click();
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスキーのインポートに失敗しました",
                variant: "destructive",
            });
        }
    };

    useEffect(() => {
        if (open) {
            fetchPasskeys();
        }
    }, [open]);

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle>パスキー管理</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                    <Button
                        className="w-full"
                        onClick={() => setShowRegistration(true)}
                    >
                        <PlusIcon className="w-5 h-5 text-white" /> パスキー
                    </Button>
                    <Button
                        variant="outline"
                        onClick={handleImport}
                    >
                        輸入
                    </Button>
                    {isLoading ? (
                        <div className="flex justify-center py-4">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                        </div>
                    ) : (
                        <>
                            {passkeys.length === 0 ? (
                                <div className="text-center py-4 text-gray-500">
                                    登録されているパスキーはありません
                                </div>
                            ) : (
                                passkeys.map((passkey) => (
                                    <div
                                        key={passkey.id}
                                        className="flex items-center justify-between p-4 border rounded-lg"
                                    >
                                        <div className="flex items-center space-x-3">
                                            <FingerPrintIcon className="w-5 h-5 text-gray-500" />
                                            <div>
                                                <p className="font-medium">{passkey.name}</p>
                                                <p className="text-sm text-gray-500">
                                                    登録日: {new Date(passkey.createdAt).toLocaleDateString('ja-JP')}
                                                    {passkey.lastUsed && (
                                                        <> • 最終使用: {new Date(passkey.lastUsed).toLocaleDateString('ja-JP')}</>
                                                    )}
                                                </p>
                                                <p className="text-sm text-gray-500">
                                                    ID: {passkey.credentialId}
                                                </p>
                                            </div>
                                        </div>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => deletePasskey(passkey.credentialId)}
                                        >
                                            <TrashIcon className="w-4 h-4 text-red-500" />
                                        </Button>
                                    </div>
                                ))
                            )}
                        </>
                    )}
                </div>
                <PasskeyRegistration
                    open={showRegistration}
                    onOpenChange={setShowRegistration}
                    onSuccess={fetchPasskeys}
                />
            </DialogContent>
        </Dialog>
    );
}