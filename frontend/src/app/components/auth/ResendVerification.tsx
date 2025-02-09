import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { api } from "@/lib/api-client";

export function ResendVerification({ email }: { email: string }) {
    const [isLoading, setIsLoading] = useState(false);
    const { toast } = useToast();

    const handleResend = async () => {
        setIsLoading(true);
        try {
            await api.auth.resendVerification(email);
            toast({
                title: "メール送信完了",
                description: "確認メールを再送信しました",
            });
        } catch (error) {
            toast({
                title: "エラー",
                description: "メールの再送信に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="text-center mt-4">
            <p className="text-sm text-gray-600">
                確認メールが届きませんでしたか？
            </p>
            <Button
                variant="link"
                onClick={handleResend}
                disabled={isLoading}
                className="text-sm"
            >
                {isLoading ? '送信中...' : '確認メールを再送信'}
            </Button>
        </div>
    );
}