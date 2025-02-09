import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { userProfileSchema, type UserProfileData } from '@/app/types/auth';
import { StepLayout } from './StepLayout';
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
    onNext: (data: UserProfileData) => void;
    onBack: () => void;
}

export function ProfileStep({ onNext, onBack }: ProfileStepProps) {
    const form = useForm<UserProfileData>({
        resolver: zodResolver(userProfileSchema),
        defaultValues: {
            firstName: '',
            lastName: '',
            phone: '',
            department: '',
        },
    });

    return (
        <StepLayout
            title="プロフィール情報"
            description="基本情報を入力してください"
            onBack={onBack}
        >
            <Form {...form}>
                <form onSubmit={form.handleSubmit(onNext)} className="space-y-4">
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