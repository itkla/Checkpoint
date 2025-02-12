'use client';

import { useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

export default function DashboardError({
    error,
    reset,
}: {
    error: Error;
    reset: () => void;
}) {
    const { toast } = useToast();
    useEffect(() => {
        console.error(error);
        toast({
            title: "エラー",
            description: error.message || "エラーが発生しました",
            variant: "destructive",
        });
    }, [error]);

    return (
        <div className="flex flex-col items-center justify-center h-screen">
            <h2 className="text-2xl font-bold mb-4">エラーが発生しました</h2>
            <Button onClick={reset}>再試行</Button>
        </div>
    );
}