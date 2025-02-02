import { startRegistration } from '@simplewebauthn/browser';
import { useState } from 'react';

type AuthenticationMethod = 'password' | 'passkey' | 'biometric' | 'sso';

interface AuthMethodMetadata {
    provider?: string;
    supportsPasskeys?: boolean;
    supportsBiometric?: boolean;
}

interface AuthMethod {
    type: AuthenticationMethod;
    metadata?: AuthMethodMetadata;
}

export default function LoginFlow() {
    const [email, setEmail] = useState('');
    const [error, setError] = useState<string | null>(null);
    const availableMethods: AuthMethod[] = [
        { type: 'password' },
        { type: 'passkey' },
        { type: 'biometric' },
        { type: 'sso', metadata: { provider: 'Google' } }
    ];

    const handlePasskeyRegistration = async () => {
        try {
            // Start registration
            const optionsResponse = await fetch(
                `${process.env.NEXT_PUBLIC_API_URL}/api/auth/passkey/register/start`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                }
            );

            const options = await optionsResponse.json();

            // Create passkey
            const regResponse = await startRegistration(options);

            // Complete registration
            const verificationResponse = await fetch(
                `${process.env.NEXT_PUBLIC_API_URL}/api/auth/passkey/register/complete`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email,
                        response: regResponse
                    })
                }
            );

            const verification = await verificationResponse.json();

            if (verification.success) {
                // Handle successful registration
            }
        } catch (err) {
            console.error(err);
            setError('Failed to register passkey');
        }
    };

    const handleSSOLogin = (provider: string) => {
        window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/auth/${provider}`;
    };

    const handleBiometricAuth = async () => {
        if (!window.PublicKeyCredential) {
            setError('Biometric authentication not supported');
            return;
        }

        try {
            // Similar to passkey flow but with biometric-specific options
        } catch (err) {
            console.error(err);
            setError('Biometric authentication failed');
        }
    };

    const handleMethodSelect = (method: AuthMethod) => {
        // Handle method selection
    };

    return (
        <div className="space-y-6">
            {availableMethods.map((method) => (
                <button
                    key={method.type}
                    onClick={() => handleMethodSelect(method)}
                    className="w-full p-4 border rounded-lg hover:bg-gray-50"
                >
                    {method.type === 'sso' && (
                        <div className="flex items-center">
                            {/* Add provider logos */}
                            <span>Continue with {method.metadata?.provider}</span>
                        </div>
                    )}
                    {method.type === 'passkey' && (
                        <div className="flex items-center">
                            <span>Use passkey</span>
                        </div>
                    )}
                    {method.type === 'biometric' && (
                        <div className="flex items-center">
                            <span>Use biometric authentication</span>
                        </div>
                    )}
                    {method.type === 'password' && (
                        <div className="flex items-center">
                            <span>Use password</span>
                        </div>
                    )}
                </button>
            ))}

            {/* Always show SSO options */}
            <div className="mt-6">
                <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                        <div className="w-full border-t border-gray-300" />
                    </div>
                    <div className="relative flex justify-center text-sm">
                        <span className="px-2 bg-white text-gray-500">Or continue with</span>
                    </div>
                </div>

                <div className="mt-6 grid grid-cols-3 gap-3">
                    <button
                        onClick={() => handleSSOLogin('google')}
                        className="flex items-center justify-center px-4 py-2 border rounded-lg hover:bg-gray-50"
                    >
                        Google
                    </button>
                </div>
            </div>
        </div>
    );
}