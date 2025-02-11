import { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api-client';
import type { LoginCredentials } from '@/app/types/user';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { PasskeyButton } from '@/app/components/auth/PasskeyButton';
import { useToast } from '@/hooks/use-toast';

export function LoginForm() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [errors, setErrors] = useState<{ email?: string; password?: string }>({});
    const router = useRouter();
    const { toast } = useToast();
    const searchParams = useSearchParams();

    // const [credentials, setCredentials] = useState<LoginCredentials>({
    //     email: '',
    //     password: '',
    // });

    const validateForm = (): boolean => {
        const newErrors: { email?: string; password?: string } = {};

        if (!email) {
            newErrors.email = 'メールアドレスを入力してください';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            newErrors.email = 'メールアドレスが無効です';
        }

        if (!password) {
            newErrors.password = 'パスワードを入力してください';
        } else if (password.length < 8) {
            newErrors.password = 'パスワードは8文字以上である必要があります';
        }
        
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) {
            return;
        }
        
        setIsLoading(true);

        try {
            const credentials: LoginCredentials = {
                email: email.trim(),
                password: password
            };

            console.log('Submitting credentials:', credentials); // Debug log
            const response = await api.auth.login(credentials);
            
            if (response.token) {
                toast({
                    title: "ログイン成功",
                    description: "ログインに成功しました",
                    variant: "default",
                })
            } else

            console.log(response);
            localStorage.setItem('token', response.token);

            // get previous path from query params
            const nextPath = searchParams.get('next');
            if (nextPath) {
                router.push(nextPath);
                return;
            } else {
                // perform lookup on user to see if admin; if admin, redirect to dashboard, otherwise redirect to /me
                const user = await api.users.getUser(response.user.id);
                if (user.role?.includes('1')) {
                    router.push('/dashboard');
                } else {
                    router.push('/me');
                }
            }
        } catch (error: any) {
            if (error.response?.status === 400) {
                toast({
                    title: "入力エラー",
                    description: "メールアドレスとパスワードを確認してください",
                    variant: "destructive",
                });
            } else if (error.response?.status === 401) {
                toast({
                    title: "認証エラー",
                    description: "メールアドレスまたはパスワードが正しくありません",
                    variant: "destructive",
                });
            } else {
                toast({
                    title: "エラー",
                    description: error.response?.data?.error || "ログインに失敗しました: ",
                    variant: "destructive",
                });
            }
            console.error('Login error:', error.response?.data);
            console.error('Login error:', error);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-4">
            <h1 className="text-2xl font-bold">ログイン</h1>
            <div>
                <label
                    htmlFor="email"
                    className="block text-sm/6 font-medium text-gray-700"
                >
                    メールアドレス
                </label>
                <Input
                    type="email"
                    placeholder=""
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-lg"
                    value={email}
                    onChange={(e) => {
                        setEmail(e.target.value),
                        setErrors(prev => ({ ...prev, email: undefined }))
                    }}
                    required
                />
                {errors.email && <p className="text-red-500 text-sm mt-1">{errors.email}</p>}
            </div>
            <div>
                <div className="flex items-center justify-between">
                    <label
                        htmlFor="password"
                        className="block text-sm/6 font-medium text-gray-900"
                    >
                        パスワード
                    </label>
                    <div className="text-sm">
                        <Link
                            href="/forgot-password"
                            className="font-semibold text-blue-500 hover:text-blue-700"
                        >
                            パスワード忘れた
                        </Link>
                    </div>
                </div>
                <Input
                    type="password"
                    id="password"
                    value={password}
                    onChange={(e) => {
                        setPassword(e.target.value),
                        setErrors(prev => ({ ...prev, password: undefined }))
                    }}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    required
                />
                {errors.password && <p className="text-red-500 text-sm mt-1">{errors.password}</p>}
            </div>
            <Button
                type="submit"
                className={`w-full py-6 text-lg ${
                    isLoading
                        ? 'bg-gray-800'
                        : 'bg-black hover:bg-gray-800'
                }`}
                disabled={isLoading}
            >
                {isLoading ? 'ログイン中...' : 'ログイン'}
            </Button>
            <PasskeyButton email={email} />
        </form>
    );
}

export default LoginForm;