import { useState } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import AuthButton from '@/app/components/AuthButton';
import MFADialog from '@/app/components/MFADialog';

import { PasskeyButton } from '@/app/components/auth/PasskeyButton';

interface LoginResponse {
    token?: string;
    mfa?: boolean;
    mfaToken?: string;
    error?: string;
}

const LoginForm: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [showMFA, setShowMFA] = useState(false);
    const [mfaToken, setMfaToken] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);

        const formData = new FormData(e.target as HTMLFormElement);

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                body: JSON.stringify({
                    email: formData.get('email'),
                    password: formData.get('password'),
                }),
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            const data: LoginResponse = await response.json();

            if (data.mfa) {
                setShowMFA(true);
                setMfaToken(data.mfaToken!);
            } else if (data.token) {
                // Handle successful login
                window.location.href = '/dashboard';
            } else {
                setError(data.error || 'ログインに失敗しました');
            }
        } catch (err) {
            setError('ネットワークエラーが発生しました');
        } finally {
            setIsLoading(false);
        }
    };

    const handleMFASubmit = async (code: string) => {
        try {
            const response = await fetch('/api/auth/mfa', {
                method: 'POST',
                body: JSON.stringify({
                    mfaToken,
                    code,
                }),
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            const data = await response.json();
            if (data.token) {
                window.location.href = '/dashboard';
            } else {
                setError('MFA認証に失敗しました');
            }
        } catch (err) {
            setError('ネットワークエラーが発生しました');
        }
    };

    const handlePasskeyLogin = async () => {
        try {
            setIsLoading(true);
            setError(null);

            // Start passkey authentication
            const startResponse = await fetch('/api/auth/passkey/login/start');
            const options = await startResponse.json();

            // Get credential from browser
            const credential = await startAuthentication(options);

            // Complete authentication
            const completeResponse = await fetch('/api/auth/passkey/login/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credential),
            });

            const result = await completeResponse.json();
            if (result.token) {
                window.location.href = '/dashboard';
            } else {
                setError('パスキー認証に失敗しました');
            }
        } catch (err) {
            setError('パスキー認証中にエラーが発生しました');
        } finally {
            setIsLoading(false);
        }
    };

    const handleBiometricLogin = async () => {
        // Implement biometric authentication
        // This would typically use the Web Authentication API with platform authenticator
        try {
            // Implementation would go here
            setError('生体認証は現在実装中です');
        } catch (err) {
            setError('生体認証中にエラーが発生しました');
        }
    };

    return (
        <>
            <form onSubmit={handleSubmit} className="mt-4 px-6">
                <h1 className="text-left text-2xl font-bold mt-4">ログイン</h1>
                {error && (
                    <div className="my-4 p-3 bg-red-100 text-red-700 rounded">
                        {error}
                    </div>
                )}
                <div className="my-4">
                    <label htmlFor="email" className="block text-sm/6 font-medium text-gray-700">
                        メールアドレス
                    </label>
                    <input
                        type="email"
                        name="email"
                        id="email"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        required
                        disabled={isLoading}
                    />
                </div>
                <div className="my-4">
                    <div className="flex items-center justify-between">
                        <label htmlFor="password" className="block text-sm/6 font-medium text-gray-900">
                            パスワード
                        </label>
                        <div className="text-sm">
                            <a href="#" className="font-semibold text-blue-500 hover:text-blue-700">
                                パスワード忘れた
                            </a>
                        </div>
                    </div>
                    <input
                        type="password"
                        name="password"
                        id="password"
                        className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        required
                        disabled={isLoading}
                    />
                </div>
                <div className="my-4">
                    <AuthButton type="submit" primary disabled={isLoading}>
                        {isLoading ? 'ログイン中...' : 'ログイン'}
                    </AuthButton>
                    <div className="flex flex-row">
                        <PasskeyButton />
                        {/* <AuthButton onClick={handleBiometricLogin} disabled={isLoading}>
                            生体認証でログイン
                        </AuthButton> */}
                    </div>
                </div>
            </form>

            <MFADialog
                isOpen={showMFA}
                onSubmit={handleMFASubmit}
                onClose={() => setShowMFA(false)}
            />
        </>
    );
};

export default LoginForm;