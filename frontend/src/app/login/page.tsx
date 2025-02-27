"use client";

import LoginForm from '@/app/components/LoginForm';
import SocialLogin from '@/app/components/SocialLogin';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect } from 'react';
import Link from 'next/link';
// import { PasskeyButton } from '@/app/components/auth/PasskeyButton';

// check if user is already logged in, redirect to /me if true
// if (localStorage.getItem('token')) {
//     const router = useRouter();
//     router.push('/me');
// }

export default function LoginPage() {
    const searchParams = useSearchParams();
    const next = searchParams.get('next');
    
    const router = useRouter();
    useEffect(() => {
        if (localStorage.getItem('token')) {
            router.push('/me');
        }
    }, [router]);
    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-100">
            <div>
                <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-2xl">
                    <img
                        src="/logo.svg"
                        alt="logo"
                        className="mx-auto rounded-full w-[100px] h-[100px]"
                    />
                    <LoginForm />
                    <div className="text-xs text-center pt-4">
                        <span className="text-gray-500">アカウント持ってない？</span>{' '}
                        {next ? (
                            <Link href={`/register?next=${next}`} className="text-blue-500 hover:text-blue-700">
                                登録する
                            </Link>
                        ) : (
                            <Link href="/register" className="text-blue-500 hover:text-blue-700">
                                登録する
                            </Link>
                        )}
                    </div>
                    <SocialLogin />
                </div>
                <div className="text-xs text-[65%] px-8 pt-4 text-gray-500">
                        <span>
                            続行すると、利用規約とプライバシーポリシーに同意するものとします。
                        </span>
                </div>
            </div>
        </div>
    );
}