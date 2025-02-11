import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { AnimatePresence } from 'framer-motion';
import { ProgressIndicator } from './registration/ProgressIndicator';
import { EmailStep } from './registration/EmailStep';
import { MethodStep } from './registration/MethodStep';
import { ProfileStep } from './registration/ProfileStep';
import { DetailStep } from './registration/DetailStep';
import { ConfirmStep } from './registration/ConfirmStep';
import { registrationSteps, type AuthState, type RegistrationStep } from '@/app/types/auth';
import { useToast } from '@/hooks/use-toast';

export function RegistrationForm() {
    const [step, setStep] = useState<RegistrationStep>('email');
    const [registrationData, setRegistrationData] = useState<AuthState>({
        email: '',
        authMethod: 'password',
        profile: {
            firstName: '',
            lastName: '',
            phone: '',
            department: '',
            address: {
                street: '',
                city: '',
                state: '',
                zip: '',
                country: '',
            }
        },
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

    useEffect(() => {
        async function checkPhone() {
            if (registrationData.phone) {
                try {
                    const existsResponse = await api.users.userExists(registrationData.phone);
                    if (existsResponse.exists) {
                        // Delay the toast call so it doesn’t occur during render.
                        setTimeout(() => {
                            toast({
                                title: "電話番号が既に存在します",
                                description: "別の電話番号を入力してください",
                                variant: "destructive",
                            });
                        }, 0);
                        // Optionally, update state to prevent proceeding.
                        setRegistrationData(prev => ({ ...prev, phoneError: true }));
                    }
                } catch (error) {
                    // Handle error
                }
            }
        }
        checkPhone();
    }, [registrationData.phone]);

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
                        initialProfile={registrationData.profile}
                        onNext={(profile) => {
                            updateRegistrationData({ profile });
                            nextStep();
                        }}
                        onBack={prevStep}
                    />
                );
            case 'details':
                return (
                    <DetailStep
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