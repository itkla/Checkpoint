'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { emailSchema } from '@/app/types/auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { EnvelopeIcon } from '@heroicons/react/24/outline';
import { api } from '@/lib/api-client';
import Link from 'next/link';
import { ArrowLeftIcon } from '@heroicons/react/24/solid';
import { Arrow } from '@radix-ui/react-select';

export default function PasswordResetPage() {
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  const form = useForm({
    resolver: zodResolver(emailSchema),
  });

  const onSubmit = async (data: { email: string }) => {
    setIsLoading(true);
    try {
      await api.auth.requestPasswordReset(data.email);
      setIsSubmitted(true);
    } catch (error) {
      toast({
        title: "エラー",
        description: "パスワードリセットメールの送信に失敗しました",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (isSubmitted) {
    return (
      <div className="flex justify-center items-center min-h-screen bg-gray-100">
        <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-[5%]">
          <div className="text-center">
            <EnvelopeIcon className="mx-auto h-12 w-12 text-blue-500" />
            <h2 className="mt-4 text-2xl font-bold">メールを送信しました</h2>
            <p className="mt-4 text-gray-600">
              パスワードリセット用のリンクをメールでお送りしました。
              メールをご確認ください。
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100">
      <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-[5%]">
        <h1 className="text-2xl font-bold text-center">パスワードリセット</h1>
        <p className="mt-2 text-gray-600 text-center">
          アカウントに登録されているメールアドレスを入力してください
        </p>

        <form onSubmit={form.handleSubmit(onSubmit)} className="mt-8 space-y-6">
          <div>
            <Input
              {...form.register("email")}
              type="email"
              placeholder="メールアドレス"
              className={`w-full ${form.formState.errors.email ? "border-red-500" : ""}`}
            />
            {form.formState.errors.email && (
              <p className="mt-1 text-sm text-red-500">
                {form.formState.errors.email.message}
              </p>
            )}
          </div>

          <Button
            type="submit"
            className="w-full py-6"
            disabled={isLoading}
          >
            {isLoading ? '送信中...' : 'リセットリンクを送信'}
          </Button>
        </form>
        <Link href="/login" className="block text-left text-sm mt-4 text-black hover:text-gray-800 transition-colors">
          <ArrowLeftIcon className="h-4 w-4 inline-block mr-1" />戻る
        </Link>
      </div>
      
    </div>
  );
}