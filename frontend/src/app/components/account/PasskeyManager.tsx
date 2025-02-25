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
import { Fingerprint, Trash, Plus } from 'lucide-react';
import { PasskeyRegistration } from './PasskeyRegistration';
import { exportCredential, importCredential } from '@/lib/webauthn';
import { 
    DropdownMenu, 
    DropdownMenuTrigger, 
    DropdownMenuContent, 
    DropdownMenuItem 
} from "@/components/ui/dropdown-menu";
import { MoreVertical, FileInput, FileOutput } from "lucide-react";

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

            const blob = new Blob([JSON.stringify(exportedKey)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'passkey-backup.json';
            a.click();
            URL.revokeObjectURL(url);
            
            toast({
                title: "成功",
                description: "パスキーをエクスポートしました",
            });
        } catch (error) {
            console.error('Export error:', error);
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
                    try {
                        const credentialData = JSON.parse(e.target?.result as string);
                        await importCredential(credentialData);
                        fetchPasskeys(); // Refresh the list
                        toast({
                            title: "成功",
                            description: "パスキーをインポートしました",
                        });
                    } catch (error) {
                        console.error('Import parsing error:', error);
                        toast({
                            title: "エラー",
                            description: "無効なパスキーデータです",
                            variant: "destructive",
                        });
                    }
                };
                reader.readAsText(file);
            };
            input.click();
        } catch (error) {
            console.error('Import error:', error);
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
                <div className="flex gap-2">
                    <Button
                        className="flex-1"
                        onClick={() => setShowRegistration(true)}
                    >
                        <Plus className="w-5 h-5 mr-2" /> 新しいパスキー
                    </Button>
                    <Button variant="outline" size="icon" onClick={handleImport}>
                        <FileInput className="h-4 w-4" />
                    </Button>
                </div>
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
                                            <Fingerprint className="w-5 h-5 text-gray-500" />
                                            <div>
                                                <p className="font-medium">{passkey.name}</p>
                                                <p className="text-sm text-gray-500">
                                                    登録日: {new Date(passkey.createdAt).toLocaleDateString('ja-JP')}
                                                    {passkey.lastUsed && (
                                                        <> • 最終使用: {new Date(passkey.lastUsed).toLocaleDateString('ja-JP')}</>
                                                    )}
                                                </p>
                                                <p className="text-xs text-gray-400 truncate max-w-[200px]">
                                                    ID: {passkey.credentialId}
                                                </p>
                                            </div>
                                        </div>
                                        <div className="flex items-center">
                                            <DropdownMenu>
                                                <DropdownMenuTrigger asChild>
                                                    <Button variant="ghost" size="sm">
                                                        <MoreVertical className="h-4 w-4" />
                                                    </Button>
                                                </DropdownMenuTrigger>
                                                <DropdownMenuContent align="end">
                                                    <DropdownMenuItem onClick={() => handleExport(passkey.credentialId)}>
                                                        <FileOutput className="w-4 h-4 mr-2" />
                                                        エクスポート
                                                    </DropdownMenuItem>
                                                    <DropdownMenuItem 
                                                        onClick={() => deletePasskey(passkey.credentialId)}
                                                        className="text-red-500"
                                                    >
                                                        <Trash className="w-4 h-4 mr-2" />
                                                        削除
                                                    </DropdownMenuItem>
                                                </DropdownMenuContent>
                                            </DropdownMenu>
                                        </div>
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