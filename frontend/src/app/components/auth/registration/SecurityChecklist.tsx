import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline';

interface SecurityChecklistProps {
    password: string;
}

export function SecurityChecklist({ password }: SecurityChecklistProps) {
    const checks = [
        {
            label: '8文字以上',
            valid: password.length >= 8,
        },
        {
            label: '大文字を含む',
            valid: /[A-Z]/.test(password),
        },
        {
            label: '小文字を含む',
            valid: /[a-z]/.test(password),
        },
        {
            label: '数字を含む',
            valid: /[0-9]/.test(password),
        },
        {
            label: '特殊文字を含む',
            valid: /[@$!%*?&]/.test(password),
        },
    ];

    return (
        <div className="mt-4">
            <h3 className="text-sm font-medium text-gray-700 mb-2">
                パスワード要件:
            </h3>
            <ul className="space-y-2">
                {checks.map(({ label, valid }) => (
                    <li
                        key={label}
                        className="flex items-center text-sm"
                    >
                        {valid ? (
                            <CheckCircleIcon className="w-4 h-4 text-green-500 mr-2" />
                        ) : (
                            <XCircleIcon className="w-4 h-4 text-red-500 mr-2" />
                        )}
                        <span className={valid ? 'text-green-700' : 'text-gray-600'}>
                            {label}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
}