import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';
import { ComputerDesktopIcon, DevicePhoneMobileIcon, QuestionMarkCircleIcon } from '@heroicons/react/24/outline';

interface Session {
    id: string;
    device: string;
    browser: string;
    location: string;
    lastActive: string;
    current: boolean;
}

export function SessionManager({ open, onOpenChange }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const [sessions, setSessions] = useState<Session[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const { toast } = useToast();

    const fetchSessions = async () => {
        try {
            const response = await api.auth.getSessions();
            setSessions(response);
        } catch (error) {
            toast({
                title: "エラー",
                description: "セッション情報の取得に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoading(false);
        }
    };

    const revokeSession = async (sessionId: string) => {
        try {
            await api.auth.revokeSession(sessionId);
            setSessions(prev => prev.filter(s => s.id !== sessionId));
            toast({
                title: "成功",
                description: "セッションを終了しました",
            });
        } catch (error) {
            toast({
                title: "エラー",
                description: "セッションの終了に失敗しました",
                variant: "destructive",
            });
        }
    };

    const revokeAllSessions = async () => {
        try {
            await api.auth.revokeAllSessions();
            // Only keep current session in the list
            setSessions(prev => prev.filter(s => s.current));
            toast({
                title: "成功",
                description: "他のすべてのセッションを終了しました",
            });
        } catch (error) {
            toast({
                title: "エラー",
                description: "セッションの終了に失敗しました",
                variant: "destructive",
            });
        }
    };

    useEffect(() => {
        if (open) {
            fetchSessions();
        }
    }, [open]);

    const getDeviceIcon = (device: string) => {
        if (device.toLowerCase().includes('mobile')) {
            return <DevicePhoneMobileIcon className="w-6 h-6" />;
        }
        if (device.toLowerCase().includes('desktop')) {
            return <ComputerDesktopIcon className="w-6 h-6" />;
        }
        return <QuestionMarkCircleIcon className="w-6 h-6" />;
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-2xl">
                <DialogHeader>
                    <DialogTitle>アクティブなセッション</DialogTitle>
                </DialogHeader>

                <div className="space-y-4">
                    {sessions.length > 1 && (
                        <div className="flex justify-end">
                            <Button
                                variant="outline"
                                onClick={revokeAllSessions}
                            >
                                他のすべてのセッションを終了
                            </Button>
                        </div>
                    )}
                    {isLoading ? (
                        <div className="flex justify-center py-4">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                        </div>
                    ) : (
                        sessions.map((session) => (
                            <div
                                key={session.id}
                                className="flex items-center justify-between p-4 border rounded-lg overflow-auto"
                            >
                                <div className="flex items-center space-x-4">
                                    {getDeviceIcon(session.device)}
                                    <div>
                                        <p className="font-medium">
                                            {session.browser} on {session.device}
                                            {session.current && (
                                                <span className="ml-2 text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">
                                                    現在のセッション
                                                </span>
                                            )}
                                        </p>
                                        <p className="text-sm text-gray-500">
                                            {session.location} • 最終アクティブ: {
                                                new Date(session.lastActive).toLocaleString('ja-JP')
                                            }
                                        </p>
                                    </div>
                                </div>
                                {!session.current && (
                                    <Button
                                        variant="destructive"
                                        onClick={() => revokeSession(session.id)}
                                    >
                                        終了
                                    </Button>
                                )}
                            </div>
                        ))
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}