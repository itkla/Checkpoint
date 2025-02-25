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
import { Badge } from "@/components/ui/badge"

interface ProfileStepProps {
    initialProfile: UserProfileData;
    onNext: (data: UserProfileData & { profilePicture?: File; preview?: string }) => void;
    onBack: () => void;
}

export function ProfileStep({ initialProfile, onNext, onBack }: ProfileStepProps) {
    const form = useForm<UserProfileData>({
        resolver: zodResolver(userProfileSchema),
        defaultValues: {
            first_name: initialProfile.first_name || '',
            last_name: initialProfile.last_name || '',
            phone: initialProfile.phone || '',
            department: initialProfile.department || '',
            address: {
                street: initialProfile.address?.street || '',
                street2: initialProfile.address?.street2 || '',
                city: initialProfile.address?.city || '',
                state: initialProfile.address?.state || '',
                zip: initialProfile.address?.zip || '',
                country: initialProfile.address?.country || '',
            },
            dateOfBirth: initialProfile.dateOfBirth || undefined,
        },
    });

    const [profilePicture, setProfilePicture] = useState<File | undefined>(undefined);
    const [preview, setPreview] = useState<string | undefined>(undefined);

    useEffect(() => {
        if (profilePicture) {
            const objectUrl = URL.createObjectURL(profilePicture);
            setPreview(objectUrl);
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
                    onNext({ ...data, profilePicture, preview });
                })} className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <FormField
                            control={form.control}
                            name="last_name"
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
                            name="first_name"
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
                                <FormLabel>電話番号</FormLabel>
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
                                <FormLabel>部署 <Badge variant="outline" className="text-gray-400">任意</Badge></FormLabel>
                                <FormControl>
                                    <Input {...field} />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <FormField
                        control={form.control}
                        name="dateOfBirth"
                        render={({ field }) => (
                            <FormItem>
                                <FormLabel>生年月日 <Badge variant="outline" className="text-gray-400">任意</Badge></FormLabel>
                                <FormControl>
                                    <Input
                                        type="date"
                                        value={
                                            field.value
                                                ? new Date(field.value).toISOString().substring(0, 10)
                                                : ''
                                        }
                                        onChange={(e) => {
                                            const dateValue = e.target.value;
                                            field.onChange(dateValue ? new Date(dateValue) : undefined);
                                        }}
                                        onBlur={field.onBlur}
                                        name={field.name}
                                    />
                                </FormControl>
                                <FormMessage />
                            </FormItem>
                        )}
                    />

                    <div className="mt-6 bg-gray-50 p-4 rounded-lg">
                        <h3 className="text-sm font-medium text-gray-700 mb-2">住所</h3>
                        <div className="grid grid-cols-1 gap-4">
                            <FormField
                                control={form.control}
                                name="address.country"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>国</FormLabel>
                                        <FormControl>
                                            <Input {...field} placeholder="国名" />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                            <div className="grid grid-cols-3 gap-4">
                                <FormField
                                    control={form.control}
                                    name="address.zip"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>郵便番号</FormLabel>
                                            <FormControl>
                                                <Input {...field} placeholder="例: 160-0023" />
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
                                            <FormLabel>州/都道府県</FormLabel>
                                            <FormControl>
                                                <Input {...field} placeholder="例: 東京都" />
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
                                            <FormLabel>区市町村</FormLabel>
                                            <FormControl>
                                                <Input {...field} placeholder="例: 新宿区" />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </div>
                            <FormField
                                control={form.control}
                                name="address.street"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>番地</FormLabel>
                                        <FormControl>
                                            <Input {...field} placeholder="例: 新宿1-7-3" />
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
                                        <FormLabel>部屋番号 (任意)</FormLabel>
                                        <FormControl>
                                            <Input {...field} placeholder="例: 192号室" />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />
                        </div>
                    </div>


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