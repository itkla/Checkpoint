"use client";

import { Button } from '@/components/ui/button';
import { ArrowLeftEndOnRectangleIcon } from '@heroicons/react/24/outline';

export function SignOutButton() {
    const handleSignOut = () => {
        localStorage.removeItem('token');
        if (typeof window !== 'undefined') {
            window.location.href = '/login';
        }
        window.location.href = '/login';
    };

    return (
        <Button
            variant="outline"
            className="py-2 px-4"
            onClick={handleSignOut}
        >
            <ArrowLeftEndOnRectangleIcon />ログアウト
        </Button>
    );
}