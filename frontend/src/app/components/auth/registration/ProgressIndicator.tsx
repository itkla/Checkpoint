// components/auth/registration/ProgressIndicator.tsx
import { motion } from 'framer-motion';
import { StepConfig } from '@/app/types/auth';

interface ProgressIndicatorProps {
    steps: StepConfig[];
    currentStep: number;
}

export function ProgressIndicator({ steps, currentStep }: ProgressIndicatorProps) {
    return (
        <div className="mb-8">
            <div className="flex justify-between">
                {steps.map((step, index) => (
                    <div key={step.key} className="relative flex flex-col items-center">
                        <motion.div
                            className={`w-8 h-8 rounded-full flex items-center justify-center ${index <= currentStep ? 'bg-blue-500' : 'bg-gray-300'
                                }`}
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            transition={{ delay: index * 0.1 }}
                        >
                            <span className="text-white text-sm">
                                {index + 1}
                            </span>
                        </motion.div>
                        <span className="absolute top-10 text-xs text-gray-600 whitespace-nowrap">
                            {step.title}
                        </span>
                        {index < steps.length - 1 && (
                            <div
                                className={`absolute top-4 left-8 w-[calc(100%-2rem)] h-0.5 -z-10 ${index < currentStep ? 'bg-blue-500' : 'bg-gray-300'
                                    }`}
                            />
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}