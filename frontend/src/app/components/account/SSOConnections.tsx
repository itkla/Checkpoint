import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api-client';

interface SSOConnection {
    provider: 'google' | 'line';
    connected: boolean;
    email?: string;
    connectedAt?: string;
}

export function SSOConnections() {
    const [connections, setConnections] = useState<SSOConnection[]>([]);
    const { toast } = useToast();

    const handleGoogleLogin = () => {
        api.auth.initiateGoogleLogin();
    };

    const handleLineLogin = () => {
        api.auth.initiateLineLogin();
    };

    return (
        <div className="space-y-4">
            <h3 className="font-medium">SNS連携</h3>

            <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-2">
                        <img src="/assets/google.svg" alt="Google" className="w-6 h-6" />
                        <div className="flex flex-col">
                            <span className="font-medium">Google</span>
                            <span className="text-sm text-gray-500">
                                {connections.find(c => c.provider === 'google')?.connected
                                    ? `連携済み (${connections.find(c => c.provider === 'google')?.email})`
                                    : '未連携'}
                            </span>
                        </div>
                    </div>
                    <Button
                        variant="outline"
                        onClick={handleGoogleLogin}
                    >
                        {connections.find(c => c.provider === 'google')?.connected
                            ? '再連携'
                            : '連携する'}
                    </Button>
                </div>

                <div className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-2">
                        <img src="/assets/line.png" alt="LINE" className="w-6 h-6" />
                        <div className="flex flex-col">
                            <span className="font-medium">LINE</span>
                            <span className="text-sm text-gray-500">
                                {connections.find(c => c.provider === 'line')?.connected
                                    ? '連携済み'
                                    : '未連携'}
                            </span>
                        </div>
                    </div>
                    <Button
                        variant="outline"
                        onClick={handleLineLogin}
                    >
                        {connections.find(c => c.provider === 'line')?.connected
                            ? '再連携'
                            : '連携する'}
                    </Button>
                </div>
            </div>
        </div>
    );
}