import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { userProfileSchema, type UserProfileData } from '@/app/types/auth';
import { StepLayout } from './StepLayout';
import { ProfilePictureUpload } from './ProfilePictureUpload';
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

interface ProfileStepProps {
    initialProfile: UserProfileData;
    onNext: (data: UserProfileData & { profilePicture?: File; preview?: string }) => void;
    onBack: () => void;
}

export function ProfileStep({ initialProfile, onNext, onBack }: ProfileStepProps) {
    const form = useForm<UserProfileData>({
        resolver: zodResolver(userProfileSchema),
        defaultValues: {
            firstName: initialProfile.firstName || '',
            lastName: initialProfile.lastName || '',
            phone: initialProfile.phone || '',
            department: initialProfile.department || '',
        },
    });

    const [profilePicture, setProfilePicture] = useState<File | undefined>(undefined);
    const [preview, setPreview] = useState<string | undefined>(undefined);

    useEffect(() => {
        if (profilePicture) {
            const objectUrl = URL.createObjectURL(profilePicture);
            setPreview(objectUrl);
            // Free memory when component unmounts or file changes.
            return () => URL.revokeObjectURL(objectUrl);
        }
    }, [profilePicture]);

    return (
        <StepLayout
            title="プロフィール情報"
            description="基本情報を入力してください"
            onBack={onBack}
        >
            <ProfilePictureUpload
                preview={preview}
                onFileSelect={setProfilePicture}
            />
            <Form {...form}>
                <form onSubmit={form.handleSubmit(data => {
                    // Pass along profile data along with picture info
                    onNext({ ...data, profilePicture, preview });
                })} className="space-y-4">
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
                        name="phone"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>電話番号 (任意)</FormLabel>
                                <FormControl>
                                    <Input {...field} type="tel" />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <FormField
                        control={form.control}
                        name="department"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>部署 (任意)</FormLabel>
                                <FormControl>
                                    <Input {...field} />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <div className="flex justify-between pt-4">
                        <Button type="button" variant="ghost" onClick={onBack}>
                            戻る
                        </Button>
                        <Button type="submit">次へ</Button>
                    </div>
                </form>
            </Form>
        </StepLayout>
    );
}