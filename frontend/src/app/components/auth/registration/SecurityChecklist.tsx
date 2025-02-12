import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline';
import { validatePassword } from '@/lib/passwordValidation';

interface SecurityChecklistProps {
    password: string;
}

export function SecurityChecklist({ password }: SecurityChecklistProps) {
    const validations = validatePassword(password);

    const checks = [
        { label: '8文字以上', valid: validations.isLongEnough },
        { label: '大文字を含む', valid: validations.hasUppercase },
        { label: '小文字を含む', valid: validations.hasLowercase },
        { label: '数字を含む', valid: validations.hasDigit },
        { label: '特殊文字を含む', valid: validations.hasSpecialChar },
    ];

    return (
        <div className="mt-4">
            <h3 className="text-sm font-medium text-gray-700 mb-2">
                パスワード要件:
            </h3>
            <ul className="space-y-2">
                {checks.map(({ label, valid }) => (
                    <li key={label} className="flex items-center text-sm">
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