import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence } from 'framer-motion';
import { ProgressIndicator } from './registration/ProgressIndicator';
import { EmailStep } from './registration/EmailStep';
import { MethodStep } from './registration/MethodStep';
import { ProfileStep } from './registration/ProfileStep';
import { DetailsStep } from './registration/DetailStep';
import { ConfirmStep } from './registration/ConfirmStep';
import { registrationSteps, type AuthState, type RegistrationStep } from '@/app/types/auth';
import { useToast } from '@/hooks/use-toast';

export function RegistrationForm() {
    const [step, setStep] = useState<RegistrationStep>('email');
    const [registrationData, setRegistrationData] = useState<AuthState>({
        email: '',
        authMethod: 'password',
    });
    const router = useRouter();
    const { toast } = useToast();
    const currentStepIndex = registrationSteps.findIndex(s => s.key === step);

    const updateRegistrationData = (data: Partial<AuthState>) => {
        setRegistrationData(prev => ({ ...prev, ...data }));
    };

    const nextStep = () => {
        const currentIndex = registrationSteps.findIndex(s => s.key === step);
        if (currentIndex < registrationSteps.length - 1) {
            setStep(registrationSteps[currentIndex + 1].key);
        }
    };

    const prevStep = () => {
        const currentIndex = registrationSteps.findIndex(s => s.key === step);
        if (currentIndex > 0) {
            setStep(registrationSteps[currentIndex - 1].key);
        }
    };

    const renderStep = () => {
        switch (step) {
            case 'email':
                return (
                    <EmailStep
                        initialEmail={registrationData.email}
                        onNext={(email) => {
                            updateRegistrationData({ email });
                            nextStep();
                        }}
                    />
                );
            case 'method':
                return (
                    <MethodStep
                        onNext={(method) => {
                            updateRegistrationData(method);
                            nextStep();
                        }}
                        onBack={prevStep}
                    />
                );
            case 'profile':
                return (
                    <ProfileStep
                        onNext={(profile) => {
                            updateRegistrationData({ profile });
                            nextStep();
                        }}
                        onBack={prevStep}
                    />
                );
            case 'details':
                return (
                    <DetailsStep
                        authMethod={registrationData.authMethod}
                        onNext={(details) => {
                            updateRegistrationData(details);
                            nextStep();
                        }}
                        onBack={prevStep}
                    />
                );
            case 'confirm':
                return (
                    <ConfirmStep
                        registrationData={registrationData}
                        onBack={prevStep}
                        onComplete={() => {
                            toast({
                                title: "登録完了",
                                description: "アカウントが正常に作成されました",
                            });
                            router.push('/login');
                        }}
                    />
                );
            default:
                return null;
        }
    };

    return (
        <div className="w-full max-w-lg mx-auto">
            <ProgressIndicator
                steps={registrationSteps}
                currentStep={currentStepIndex}
            />
            <AnimatePresence mode="wait">
                {renderStep()}
            </AnimatePresence>
        </div>
    );
}