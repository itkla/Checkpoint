import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';

interface StepLayoutProps {
    title: string;
    description: string;
    children: React.ReactNode;
    onBack?: () => void;
    showBack?: boolean;
}

export function StepLayout({
    title,
    description,
    children,
    onBack,
    showBack = true,
}: StepLayoutProps) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
        >
            <div className="text-center">
                <h2 className="text-2xl font-bold">{title}</h2>
                <p className="text-gray-600 mt-2">{description}</p>
            </div>

            {children}

            {showBack && onBack && (
                <div className="mt-4">
                    <Button
                        variant="ghost"
                        onClick={onBack}
                        className="text-gray-600"
                    >
                        戻る
                    </Button>
                </div>
            )}
        </motion.div>
    );
}