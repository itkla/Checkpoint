"use client";

import { Button } from '@/components/ui/button';

export function SignOutButton() {
    const handleSignOut = () => {
        localStorage.removeItem('token');
        window.location.reload();
    };

    return (
        <Button
            variant="outline"
            className="py-2 px-4"
            onClick={handleSignOut}
        >
            ログアウト
        </Button>
    );
}