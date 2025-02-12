import { useState } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { User } from "@/app/types/user";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Toast } from "@/components/ui/toast";
import { userSchema } from "@/app/types/user";

// export function EditUserDialog({
//     user,
//     open,
//     onOpenChange,
//     onSave,
// }: EditUserDialogProps) {
//     const form = useForm<User>({
//         resolver: zodResolver(userSchema),
//         defaultValues: user || {},
//     });

//     const handleSubmit = async (data: User) => {
//         try {
//             await onSave(data);
//             Toast({
//                 title: "成功",
//                 description: "ユーザー情報を更新しました。",
//             });
//             onOpenChange(false);
//         } catch (error) {
//             toast({
//                 title: "エラー",
//                 description: "ユーザー情報の更新に失敗しました。",
//                 variant: "destructive",
//             });
//         }
//     };

//     return (
//         <Dialog open={open} onOpenChange={onOpenChange}>
//             <DialogContent className="sm:max-w-xl">
//                 <Form {...form}>
//                     <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
//                         <FormField
//                             control={form.control}
//                             name="name"
//                             render={({ field }) => (
//                                 <FormItem>
//                                     <FormLabel>名前</FormLabel>
//                                     <FormControl>
//                                         <Input {...field} />
//                                     </FormControl>
//                                     <FormMessage />
//                                 </FormItem>
//                             )}
//                         />
//                         {/* Add other form fields similarly */}
//                     </form>
//                 </Form>
//             </DialogContent>
//         </Dialog>
//     );
// }

interface EditUserDialogProps {
    user: User | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSave: (user: User) => void;
}

export function EditUserDialog({
    user,
    open,
    onOpenChange,
    onSave,
}: EditUserDialogProps) {
    const [formData, setFormData] = useState<Partial<User>>(user || {});
    const [isSubmitting, setIsSubmitting] = useState(false);

    if (!user) return null;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        try {
            await onSave({ ...user, ...formData });
            onOpenChange(false);
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-xl">
                <DialogHeader>
                    <DialogTitle>ユーザー編集</DialogTitle>
                </DialogHeader>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label htmlFor="name">名前</Label>
                            <Input
                                id="name"
                                value={formData.name || ''}
                                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="email">メールアドレス</Label>
                            <Input
                                id="email"
                                type="email"
                                value={formData.email || ''}
                                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                required
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="phone">電話番号</Label>
                            <Input
                                id="phone"
                                type="tel"
                                value={formData.phone || ''}
                                onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="department">部署</Label>
                            <Input
                                id="department"
                                value={formData.department || ''}
                                onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="role">役割</Label>
                            <Select
                                value={formData.role}
                                onValueChange={(value) => setFormData({ ...formData, role: value })}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="役割を選択" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="Admin">管理者</SelectItem>
                                    <SelectItem value="Editor">編集者</SelectItem>
                                    <SelectItem value="Viewer">閲覧者</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>

                        <div className="space-y-2">
                            <Label>アクティブ状態</Label>
                            <div className="flex items-center space-x-2">
                                <Switch
                                    checked={formData.active}
                                    onCheckedChange={(checked) =>
                                        setFormData({ ...formData, active: checked })
                                    }
                                />
                                <Label>{formData.active ? 'アクティブ' : '非アクティブ'}</Label>
                            </div>
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            type="button"
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                            disabled={isSubmitting}
                        >
                            キャンセル
                        </Button>
                        <Button type="submit" disabled={isSubmitting}>
                            {isSubmitting ? '保存中...' : '保存'}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}