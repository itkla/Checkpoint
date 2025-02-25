"use client";

import { Button } from '@/components/ui/button';
import { ArrowLeftEndOnRectangleIcon } from '@heroicons/react/24/outline';
import { LogOut } from 'lucide-react';

export function SignOut() {
    localStorage.removeItem('token');
    if (typeof window !== 'undefined') {
        window.location.href = '/login';
    }
    window.location.href = '/login';
}

export function SignOutButton() {
    const handleSignOut = () => {
        SignOut();
    };

    return (
        <Button
            variant="outline"
            className="py-2 px-4"
            onClick={handleSignOut}
        >
            <LogOut className="mr-2 h-4 w-4" /> ログアウト
        </Button>
    );
}

export default {SignOutButton, SignOut};