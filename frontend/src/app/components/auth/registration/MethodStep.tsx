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
            enabled: true,
        },
        {
            type: 'passkey' as AuthMethod,
            icon: FingerPrintIcon,
            title: 'パスキー',
            description: '生体認証や端末のセキュリティ機能を使用',
            enabled: false,
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
            enabled: false,
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
                        className={`p-4 transition-all ${
                            method.enabled 
                                ? 'cursor-pointer hover:border-blue-500' 
                                : 'cursor-not-allowed opacity-60'
                        }`}
                        onClick={() => method.enabled && method.type !== 'sso' && onNext({ authMethod: method.type })}
                        title={!method.enabled ? "この認証方法は現在開発中のため利用できません" : undefined}
                    >
                        <div className="flex items-start space-x-4">
                            <method.icon className={`w-6 h-6 ${method.enabled ? 'text-blue-500' : 'text-gray-400'}`} />
                            <div className="flex-1">
                                <h3 className="font-medium">{method.title}</h3>
                                <p className="text-sm text-gray-600">{method.description}</p>
                                {method.type === 'sso' && method.enabled && (
                                    <div className="mt-2 flex space-x-2">
                                        {method.providers?.map((provider) => (
                                            <Button
                                                key={provider.id}
                                                variant="outline"
                                                size="sm"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    onNext({
                                                        authMethod: 'sso',
                                                        ssoProvider: provider.id,
                                                    });
                                                }}
                                            >
                                                {provider.name}
                                            </Button>
                                        ))}
                                    </div>
                                )}
                                {!method.enabled && (
                                    <p className="text-xs mt-1 text-amber-500">このCheckpoint管理者は登録時にこの認証方法を有効にしていません。ただし、登録後に希望の認証方法として変更することができます。</p>
                                )}
                            </div>
                        </div>
                    </Card>
                ))}
            </div>
            <Button type="button" variant="ghost" onClick={onBack}>
                戻る
            </Button>
        </StepLayout>
    );
}