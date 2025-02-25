import { useState, useEffect, useRef } from 'react';
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
import { CheckIcon } from 'lucide-react';

export function RegistrationForm() {
    const [step, setStep] = useState<RegistrationStep>('email');
    const [registrationData, setRegistrationData] = useState<AuthState>({
        email: '',
        authMethod: 'password',
        profile: {
            first_name: '',
            last_name: '',
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
    const contentRef = useRef<HTMLDivElement>(null);
    const [hasOverflow, setHasOverflow] = useState(false);
    const router = useRouter();
    const { toast } = useToast();
    const currentStepIndex = registrationSteps.findIndex(s => s.key === step);

    const getStepDescription = (stepKey: RegistrationStep) => {
        switch (stepKey) {
            case 'email': return "メールアドレスを入力して開始";
            case 'method': return "認証方法を選択";
            case 'profile': return "あなたについて教えてください";
            case 'details': return "アカウント詳細を設定";
            case 'confirm': return "確認して登録を完了";
            default: return "";
        }
    };

    const getStepHelp = (stepKey: RegistrationStep) => {
        switch (stepKey) {
            case 'email':
                return "定期的に確認する個人用メールを使用してください。";
            case 'method':
                return "ほとんどのユーザーにはパスワードログインをお勧めします。";
            case 'profile':
                return "プロフィール情報はあなたの体験をパーソナライズするのに役立ちます。";
            case 'details':
                return "文字、数字、記号を含む8文字以上の強力なパスワードを作成してください。";
            case 'confirm':
                return "送信前に情報を慎重に確認してください。";
            default:
                return "";
        }
    };

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

    // useEffect(() => {
    //     async function checkPhone() {
    //         if (registrationData.phone) {
    //             try {
    //                 const existsResponse = await api.users.userExists(registrationData.phone);
    //                 if (existsResponse.exists) {
    //                     // Delay the toast call so it doesn’t occur during render.
    //                     setTimeout(() => {
    //                         toast({
    //                             title: "電話番号が既に存在します",
    //                             description: "別の電話番号を入力してください",
    //                             variant: "destructive",
    //                         });
    //                     }, 0);
    //                     // Optionally, update state to prevent proceeding.
    //                     setRegistrationData(prev => ({ ...prev, phoneError: true }));
    //                 }
    //             } catch (error) {
    //                 // Handle error
    //             }
    //         }
    //     }
    //     checkPhone();
    // }, [registrationData.phone]);

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

    useEffect(() => {
        const checkOverflow = () => {
            if (contentRef.current) {
                const hasContentOverflow = contentRef.current.scrollHeight > contentRef.current.clientHeight;
                setHasOverflow(hasContentOverflow);
            }
        };

        checkOverflow();
        window.addEventListener('resize', checkOverflow);

        return () => {
            window.removeEventListener('resize', checkOverflow);
        };
    }, [step]);

    return (
        <div className="w-full max-w-5xl mx-auto">
            <div className="flex flex-col md:flex-row shadow-lg rounded-lg overflow-hidden border border-gray-200 h-[650px]">
                <div className="w-full md:w-1/5 bg-gray-50 p-5">
                    <div className="sticky top-6">
                        <h2 className="text-xl font-semibold mb-6">進捗状況</h2>
                        <div className="mt-8 relative">
                            <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-gray-200"></div>

                            {registrationSteps.map((regStep, index) => {
                                const isCompleted = index < currentStepIndex;
                                const isCurrent = index === currentStepIndex;
                                const isPending = index > currentStepIndex;

                                return (
                                    <div key={regStep.key} className="relative z-10 mb-8">
                                        <div className="flex items-start">
                                            <div
                                                className={`w-6 h-6 flex-shrink-0 flex items-center justify-center rounded-full mr-3 ${isCompleted
                                                        ? "bg-green-500 text-white"
                                                        : isCurrent
                                                            ? "bg-black text-white ring-4 ring-gray-300"
                                                            : "bg-gray-200 text-gray-500"
                                                    }`}
                                            >
                                                {isCompleted ? <CheckIcon className="h-3 w-3" /> : index + 1}
                                            </div>
                                            <div className="flex flex-col">
                                                <span className={`font-medium ${isCurrent
                                                        ? "text-black"
                                                        : isCompleted
                                                            ? "text-gray-700"
                                                            : "text-gray-400"
                                                    }`}>
                                                    {regStep.title}
                                                </span>
                                                {isCurrent && (
                                                    <span className="text-sm text-gray-500 mt-1">
                                                        {getStepDescription(regStep.key)}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        {getStepHelp(step) && (
                            <div className="mt-6 p-3 bg-blue-50 rounded-md border border-blue-100">
                                <h3 className="text-sm font-medium text-blue-800 mb-1">お役立ち情報</h3>
                                <p className="text-xs text-blue-700">{getStepHelp(step)}</p>
                            </div>
                        )}
                    </div>
                </div>
                <div className="w-full md:w-4/5 relative bg-white flex flex-col">
                    <div
                        ref={contentRef}
                        className="p-6 h-[650px] overflow-y-auto flex flex-col scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-transparent"
                    >
                        <div className="flex-grow flex items-center justify-center">
                            <div className="w-full max-w-md">
                                <AnimatePresence mode="wait">
                                    {renderStep()}
                                </AnimatePresence>
                            </div>
                        </div>
                    </div>
                    {hasOverflow && (
                        <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-white to-transparent pointer-events-none"></div>
                    )}
                </div>
            </div>
        </div>
    );
}