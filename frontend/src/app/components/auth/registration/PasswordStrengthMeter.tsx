import { motion } from 'framer-motion';

interface PasswordStrengthMeterProps {
    password: string;
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
    const calculateStrength = (pwd: string): number => {
        let strength = 0;
        if (pwd.length >= 8) strength++;
        if (/[A-Z]/.test(pwd)) strength++;
        if (/[a-z]/.test(pwd)) strength++;
        if (/[0-9]/.test(pwd)) strength++;
        if (/[@$!%*?&]/.test(pwd)) strength++;
        return strength;
    };

    const strength = calculateStrength(password);
    const strengthText = [
        '非常に弱い',
        '弱い',
        '普通',
        '強い',
        '非常に強い',
    ];

    const strengthColor = [
        'bg-red-500',
        'bg-orange-500',
        'bg-yellow-500',
        'bg-green-500',
        'bg-blue-500',
    ];

    return (
        <div className="mt-2">
            <div className="flex justify-between mb-1">
                <span className="text-xs text-gray-600">パスワード強度:</span>
                <span className="text-xs font-medium text-gray-900">
                    {strengthText[strength - 1]}
                </span>
            </div>
            <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
                <motion.div
                    className={`h-full ${strengthColor[strength - 1]}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${(strength / 5) * 100}%` }}
                    transition={{ duration: 0.3 }}
                />
            </div>
        </div>
    );
}