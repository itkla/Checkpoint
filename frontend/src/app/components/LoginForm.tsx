import { useState } from 'react';
import { useRouter } from 'next/navigation';
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
    const router = useRouter();
    const { toast } = useToast();

    const [credentials, setCredentials] = useState<LoginCredentials>({
        email: '',
        password: '',
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        try {
            const response = await api.auth.login(credentials);
            console.log(response);
            localStorage.setItem('token', response.token);
            router.push('/dashboard');
        } catch (error: any) {
            toast({
                title: "エラー",
                description: error.response?.data?.error || "ログインに失敗しました",
                variant: "destructive",
            });
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
                    onChange={(e) => setEmail(e.target.value)}
                    required
                />
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
                    value={credentials.password}
                    onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                    required
                />
            </div>
            <Button type="submit" className="w-full bg-blue-500 hover:bg-blue-600" disabled={isLoading}>
                {isLoading ? 'ログイン中...' : 'ログイン'}
            </Button>
            <PasskeyButton email={email} />
        </form>
    );
}

export default LoginForm;