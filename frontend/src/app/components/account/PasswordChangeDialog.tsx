import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { z } from 'zod';
import { api } from '@/lib/api-client';
import { PasswordStrengthMeter } from '@/app/components/auth/registration/PasswordStrengthMeter';
import { SecurityChecklist } from '@/app/components/auth/registration/SecurityChecklist';

const passwordChangeSchema = z.object({
    currentPassword: z.string().min(1, "現在のパスワードを入力してください"),
    newPassword: z.string()
        .min(8, "8文字以上である必要があります")
        .regex(/[A-Z]/, "大文字を含める必要があります")
        .regex(/[a-z]/, "小文字を含める必要があります")
        .regex(/[0-9]/, "数字を含める必要があります")
        .regex(/[^A-Za-z0-9]/, "特殊文字を含める必要があります"),
    confirmPassword: z.string(),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "新しいパスワードが一致しません",
    path: ["confirmPassword"],
});

interface PasswordChangeDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function PasswordChangeDialog({
    open,
    onOpenChange,
}: PasswordChangeDialogProps) {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { toast } = useToast();
    const form = useForm({
        resolver: zodResolver(passwordChangeSchema),
        defaultValues: {
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
        },
    });

    const onSubmit = async (data: z.infer<typeof passwordChangeSchema>) => {
        setIsSubmitting(true);
        try {
            await api.auth.changePassword({
                oldPassword: data.currentPassword,
                newPassword: data.newPassword,
            });

            onOpenChange(false);
            toast({
                title: "成功",
                description: "パスワードを変更しました",
            });
            form.reset();
        } catch (error) {
            toast({
                title: "エラー",
                description: "パスワードの変更に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsSubmitting(false);
        }
    };

    const newPassword = form.watch('newPassword');

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>パスワードの変更</DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <FormField
                            control={form.control}
                            name="currentPassword"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>現在のパスワード</FormLabel>
                                    <FormControl>
                                        <Input {...field} type="password" />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="newPassword"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>新しいパスワード</FormLabel>
                                    <FormControl>
                                        <Input {...field} type="password" />
                                    </FormControl>
                                    <PasswordStrengthMeter password={field.value} />
                                    <SecurityChecklist password={field.value} />
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="confirmPassword"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>新しいパスワード (確認)</FormLabel>
                                    <FormControl>
                                        <Input {...field} type="password" />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <div className="flex justify-end space-x-2">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => onOpenChange(false)}
                                disabled={isSubmitting}
                            >
                                キャンセル
                            </Button>
                            <Button type="submit" disabled={isSubmitting}>
                                {isSubmitting ? '変更中...' : '変更'}
                            </Button>
                        </div>
                    </form>
                </Form>
            </DialogContent>
        </Dialog>
    );
}