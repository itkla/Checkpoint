import { motion } from 'framer-motion';
import { StepConfig } from '@/app/types/auth';

interface ProgressIndicatorProps {
    steps: StepConfig[];
    currentStep: number; // currentStep is the index (0-based)
}

export function ProgressIndicator({ steps, currentStep }: ProgressIndicatorProps) {
    // Calculate progress percentage; if there's only one step, avoid division by zero.
    const progressPercent = steps.length > 1
        ? Math.min((currentStep / (steps.length - 1)) * 100, 100)
        : 100;

    // Get the current step title for display
    const currentTitle = steps[currentStep]?.title || '';

    return (
        <div className="mb-16 w-full">
            <div className="relative w-full h-8 bg-gray-300 rounded overflow-hidden">
                <motion.div
                    className="h-full bg-blue-500 rounded flex items-center justify-end px-2"
                    initial={{ width: 0 }}
                    animate={{ width: `${progressPercent}%` }}
                    transition={{ duration: 0.5 }}
                >
                    <span className="text-white text-sm">{currentTitle}</span>
                </motion.div>
            </div>
        </div>
    );
}

export default ProgressIndicator;