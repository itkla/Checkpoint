import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';
import {
    ShieldCheckIcon,
    KeyIcon,
    GlobeAltIcon,
} from '@heroicons/react/24/outline';

interface ActivityLog {
    id: string;
    type: 'login' | 'password_change' | 'profile_update' | 'security_event';
    description: string;
    timestamp: string;
    metadata?: Record<string, any>;
}

export function ActivityLog({ open, onOpenChange }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const [activities, setActivities] = useState<ActivityLog[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const { toast } = useToast();

    const fetchActivities = async () => {
        try {
            const response = await api.users.getActivityLog();
            setActivities(response);
        } catch (error) {
            toast({
                title: "エラー",
                description: "アクティビティログの取得に失敗しました",
                variant: "destructive",
            });
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        if (open) {
            fetchActivities();
        }
    }, [open]);

    const getActivityIcon = (type: string) => {
        switch (type) {
            case 'login':
                return <GlobeAltIcon className="w-6 h-6 text-blue-500" />;
            case 'password_change':
                return <KeyIcon className="w-6 h-6 text-yellow-500" />;
            case 'security_event':
                return <ShieldCheckIcon className="w-6 h-6 text-red-500" />;
            default:
                return <GlobeAltIcon className="w-6 h-6 text-gray-500" />;
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-2xl">
                <DialogHeader>
                    <DialogTitle>アクティビティログ</DialogTitle>
                </DialogHeader>

                <div className="space-y-4">
                    {isLoading ? (
                        <div className="flex justify-center py-4">
                            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {activities.map((activity) => (
                                <div
                                    key={activity.id}
                                    className="flex space-x-4 p-4 border rounded-lg"
                                >
                                    <div className="flex-shrink-0">
                                        {getActivityIcon(activity.type)}
                                    </div>
                                    <div className="flex-1">
                                        <p className="font-medium">{activity.description}</p>
                                        <p className="text-sm text-gray-500">
                                            {new Date(activity.timestamp).toLocaleString('ja-JP')}
                                        </p>
                                        {activity.metadata && activity.metadata.location && (
                                            <p className="text-sm text-gray-500">
                                                場所: {activity.metadata.location}
                                            </p>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    );
}