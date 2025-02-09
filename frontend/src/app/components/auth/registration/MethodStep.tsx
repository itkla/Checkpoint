import { AuthMethod, SsoProvider } from '@/app/types/auth';
import { StepLayout } from './StepLayout';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
    KeyIcon,
    FingerPrintIcon,
    UserIcon,
} from '@heroicons/react/24/outline';

interface MethodStepProps {
    onNext: (data: { authMethod: AuthMethod; ssoProvider?: SsoProvider }) => void;
    onBack: () => void;
}

export function MethodStep({ onNext, onBack }: MethodStepProps) {
    const methods = [
        {
            type: 'password' as AuthMethod,
            icon: KeyIcon,
            title: 'パスワード',
            description: '従来のパスワードを使用してログイン',
        },
        {
            type: 'passkey' as AuthMethod,
            icon: FingerPrintIcon,
            title: 'パスキー',
            description: '生体認証や端末のセキュリティ機能を使用',
        },
        {
            type: 'sso' as AuthMethod,
            icon: UserIcon,
            title: 'SSO認証',
            description: '外部サービスのアカウントを使用',
            providers: [
                { id: 'google' as SsoProvider, name: 'Google' },
                { id: 'line' as SsoProvider, name: 'LINE' },
            ],
        },
    ];

    return (
        <StepLayout
            title="認証方法の選択"
            description="アカウントのログイン方法を選択してください"
            onBack={onBack}
        >
            <div className="space-y-4">
                {methods.map((method) => (
                    <Card
                        key={method.type}
                        className="p-4 cursor-pointer hover:border-blue-500 transition-all"
                        onClick={() => method.type !== 'sso' && onNext({ authMethod: method.type })}
                    >
                        <div className="flex items-start space-x-4">
                            <method.icon className="w-6 h-6 text-blue-500" />
                            <div className="flex-1">
                                <h3 className="font-medium">{method.title}</h3>
                                <p className="text-sm text-gray-600">{method.description}</p>
                                {method.type === 'sso' && (
                                    <div className="mt-2 flex space-x-2">
                                        {method.providers?.map((provider) => (
                                            <Button
                                                key={provider.id}
                                                variant="outline"
                                                size="sm"
                                                onClick={() => onNext({
                                                    authMethod: 'sso',
                                                    ssoProvider: provider.id,
                                                })}
                                            >
                                                {provider.name}
                                            </Button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </Card>
                ))}
            </div>
        </StepLayout>
    );
}