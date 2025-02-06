import { startAuthentication } from '@simplewebauthn/browser';
import { useState } from 'react';

interface UsePasskeyReturn {
    isLoading: boolean;
    error: string | null;
    initiatePasskeyLogin: () => Promise<void>;
}

export function usePasskey(): UsePasskeyReturn {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const initiatePasskeyLogin = async () => {
        try {
            setIsLoading(true);
            setError(null);

            // Request challenge from server
            const startResponse = await fetch('/api/auth/passkey/login/start');
            const options = await startResponse.json();

            // Get credential from browser
            const credential = await startAuthentication(options);

            // Send credential to server
            const verifyResponse = await fetch('/api/auth/passkey/login/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credential),
            });

            const verification = await verifyResponse.json();

            if (!verification.verified) {
                throw new Error('認証に失敗しました');
            }

            // Handle successful authentication
            if (verification.token) {
                // Store token or redirect as needed
                window.location.href = '/dashboard';
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : '認証に失敗しました');
            throw err;
        } finally {
            setIsLoading(false);
        }
    };

    return {
        isLoading,
        error,
        initiatePasskeyLogin,
    };
}