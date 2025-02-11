import { useState } from 'react';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';
import { useRouter } from 'next/navigation';

export function DeleteAccount({
    email,
    id,
    open,
    onOpenChange,
}: {
    email: string;
    id: string
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const [confirmation, setConfirmation] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);
    const { toast } = useToast();
    const router = useRouter();

    const handleDelete = async () => {
        if (confirmation !== email) return;

        setIsDeleting(true);
        try {
            await api.users.deleteUser(id);
            toast({
                title: "アカウント削除",
                description: "アカウントが正常に削除されました",
            });
            localStorage.removeItem('token');
            router.push('/login');
        } catch (error) {
            toast({
                title: "エラー",
                description: "アカウントの削除に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsDeleting(false);
        }
    };

    return (
        <AlertDialog open={open} onOpenChange={onOpenChange}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle>アカウントを削除しますか？</AlertDialogTitle>
                    <AlertDialogDescription>
                        この操作は取り消すことができません。すべてのデータが完全に削除されます。
                        確認のため、メールアドレスを入力してください。
                    </AlertDialogDescription>
                </AlertDialogHeader>

                <div className="my-4">
                    <Input
                        value={confirmation}
                        onChange={(e) => setConfirmation(e.target.value)}
                        placeholder={email}
                        className="w-full"
                    />
                </div>

                <AlertDialogFooter>
                    <AlertDialogCancel disabled={isDeleting}>
                        キャンセル
                    </AlertDialogCancel>
                    <AlertDialogAction
                        onClick={handleDelete}
                        disabled={confirmation !== email || isDeleting}
                        className="bg-red-500 hover:bg-red-600"
                    >
                        {isDeleting ? '削除中...' : 'アカウントを削除'}
                    </AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    );
}