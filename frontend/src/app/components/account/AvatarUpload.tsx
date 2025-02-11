import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';
import Image from 'next/image';

interface AvatarUploadProps {
    currentAvatar?: string;
    userId: string;
    onAvatarUpdate: (newAvatarUrl: string) => void;
}

export function AvatarUpload({ currentAvatar, userId, onAvatarUpdate }: AvatarUploadProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [previewUrl, setPreviewUrl] = useState<string | null>(null);
    const [isUploading, setIsUploading] = useState(false);
    const { toast } = useToast();

    const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            if (file.size > 5 * 1024 * 1024) { // 5MB limit
                toast({
                    title: "エラー",
                    description: "ファイルサイズは5MB以下にしてください",
                    variant: "destructive",
                });
                return;
            }

            setSelectedFile(file);
            const reader = new FileReader();
            reader.onloadend = () => {
                setPreviewUrl(reader.result as string);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleUpload = async () => {
        if (!selectedFile) return;

        setIsUploading(true);
        try {
            const formData = new FormData();
            formData.append('avatar', selectedFile);

            const response = await api.users.uploadAvatar(userId, formData);
            onAvatarUpdate(response.avatarUrl);
            setIsOpen(false);
            toast({
                title: "成功",
                description: "プロフィール画像を更新しました",
            });
        } catch (error) {
            toast({
                title: "エラー",
                description: "アップロードに失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsUploading(false);
        }
    };

    return (
        <>
            <div className="relative group">
                <img
                    src={currentAvatar || "https://placehold.co/100"}
                    alt="Profile"
                    className="w-24 h-24 rounded-full cursor-pointer transition-opacity group-hover:opacity-75"
                    onClick={() => setIsOpen(true)}
                />
                <div
                    className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={() => setIsOpen(true)}
                >
                    <span className="text-white bg-black bg-opacity-50 px-2 py-1 rounded text-sm">
                        変更
                    </span>
                </div>
            </div>

            <Dialog open={isOpen} onOpenChange={setIsOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>プロフィール画像の変更</DialogTitle>
                    </DialogHeader>

                    <div className="space-y-4">
                        <div className="flex justify-center">
                            <img
                                src={previewUrl || currentAvatar || "https://placehold.co/200"}
                                alt="Preview"
                                className="w-48 h-48 rounded-full object-cover"
                            />
                        </div>

                        <div className="flex flex-col items-center gap-4">
                            <input
                                type="file"
                                accept="image/*"
                                onChange={handleFileSelect}
                                className="hidden"
                                id="avatar-upload"
                            />
                            <label
                                htmlFor="avatar-upload"
                                className="cursor-pointer bg-gray-100 hover:bg-gray-200 px-4 py-2 rounded-md"
                            >
                                画像を選択
                            </label>
                            {selectedFile && (
                                <Button
                                    onClick={handleUpload}
                                    disabled={isUploading}
                                >
                                    {isUploading ? 'アップロード中...' : 'アップロード'}
                                </Button>
                            )}
                        </div>
                    </div>
                </DialogContent>
            </Dialog>
        </>
    );
}