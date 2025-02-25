import { useState, useEffect } from 'react';
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
import { api } from '@/lib/api-client';
import { userProfileSchema } from '@/app/types/auth';
import type { User } from '@/app/types/user';
import { LuPencil } from 'react-icons/lu'

interface EditProfileDialogProps {
    user: User;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onUserUpdate: (user: User) => void;
}

export function EditProfileDialog({
    user,
    open,
    onOpenChange,
    onUserUpdate,
}: EditProfileDialogProps) {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { toast } = useToast();

    // Create a custom resolver that transforms field names before validation
    const customResolver = async (data: any, context: any, options: any) => {
        // Transform data from camelCase to snake_case for validation
        const transformedData = {
            // Map firstName to first_name, lastName to last_name
            first_name: data.firstName,
            last_name: data.lastName,
            department: data.department,
            phone: data.phone,
            email: data.email,
            address: data.address,
        };

        // Use Zod resolver with transformed data
        return zodResolver(userProfileSchema)(transformedData, context, options);
    };

    const form = useForm({
        resolver: customResolver,
        defaultValues: {
            firstName: user.profile?.first_name || '',
            lastName: user.profile?.last_name || '',
            department: user.department || '',
            phone: user.profile?.phone || '',
            email: user.email,
            address: {
                street: user.profile?.address?.street || '',
                street2: user.profile?.address?.street2 || '',
                city: user.profile?.address?.city || '',
                state: user.profile?.address?.state || '',
                zip: user.profile?.address?.zip || '',
                country: user.profile?.address?.country || '',
            },
        },
    });

    useEffect(() => {
        if (user) {
            form.reset({
                firstName: user.profile?.first_name || '',
                lastName: user.profile?.last_name || '',
                department: user.department || '',
                phone: user.profile?.phone || '',
                email: user.email,
                address: {
                    street: user.profile?.address?.street || '',
                    street2: user.profile?.address?.street2 || '',
                    city: user.profile?.address?.city || '',
                    state: user.profile?.address?.state || '',
                    zip: user.profile?.address?.zip || '',
                    country: user.profile?.address?.country || '',
                },
            });
        }
    }, [user, form]);

    const onSubmit = async (data: any) => {
        setIsSubmitting(true);
        console.log(`Got data to submit:`, data);

        try {
            // Format data to match exactly what the backend expects
            const updateData = {
                ...user,
                email: data.email,
                profile: {
                    first_name: data.firstName,
                    last_name: data.lastName,
                    phone: data.phone,
                    // Make sure to include these fields to match UserSchema
                    profile_picture: user.profile?.profile_pic || '',
                    dateOfBirth: user.profile?.dateOfBirth || undefined,
                    // Format address as a proper object
                    address: {
                        street: data.address.street,
                        street2: data.address.street2,
                        city: data.address.city,
                        state: data.address.state,
                        zip: data.address.zip,
                        country: data.address.country,
                    },
                },
            };

            console.log("Sending to backend:", updateData);

            const updatedUser = await api.users.updateUser(user.id, updateData);

            onUserUpdate(updatedUser);
            onOpenChange(false);
            toast({
                title: "成功",
                description: "プロフィールを更新しました",
            });
        } catch (error) {
            console.error("API error:", error);
            toast({
                title: "エラー",
                description: "プロフィールの更新に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle className="flex flex-row items-center">
                        <LuPencil className="h-6 w-6 mr-2" /> プロフィールの編集
                    </DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <FormField
                                control={form.control}
                                name="lastName"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>姓</FormLabel>
                                        <FormControl>
                                            <Input {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            <FormField
                                control={form.control}
                                name="firstName"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>名</FormLabel>
                                        <FormControl>
                                            <Input {...field} />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                        </div>

                        <FormField
                            control={form.control}
                            name="email"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Email</FormLabel>
                                    <FormControl>
                                        <Input {...field} />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <FormField
                            control={form.control}
                            name="phone"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>電話番号</FormLabel>
                                    <FormControl>
                                        <Input {...field} type="tel" />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <fieldset className="border p-4 rounded">
                            <legend className="mb-2 text-sm font-medium">住所</legend>
                            <div className="grid grid-cols-2 gap-4">
                                <FormField
                                    control={form.control}
                                    name="address.country"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>国名</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="address.zip"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>郵便番号</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="address.state"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>都道府県</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="address.city"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>市区町村</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="address.street"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>番地</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="address.street2"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>建物名・部屋番号</FormLabel>
                                            <FormControl>
                                                <Input {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </div>
                        </fieldset>

                        <div className="flex justify-end space-x-2">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => onOpenChange(false)}
                                disabled={isSubmitting}
                            >
                                キャンセル
                            </Button>
                            <Button
                                type="submit"
                                disabled={isSubmitting}
                            >
                                {isSubmitting ? '保存中...' : '保存'}
                            </Button>
                        </div>
                    </form>
                </Form>
            </DialogContent>
        </Dialog>
    );
}