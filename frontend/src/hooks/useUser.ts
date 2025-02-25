

import { useState, useEffect } from 'react';
import { User } from '@/app/types/user';
import { UserAuthMethod } from '@/app/types/auth';
import { api } from '@/lib/api-client';
// import { cookies } from 'next/headers';

export function useUser() {
    const [user, setUser] = useState<User | null>(null);
    const [userAuth, setUserAuth] = useState<UserAuthMethod | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<Error | null>(null);

    useEffect(() => {
        const fetchUser = async () => {
            setIsLoading(true);
            try {
                const response = await api.users.me();
                // console.log('User:', response);
                const user = response.user;
                const auth = response.auth;
                console.log(auth);
                setUser(user);
                setUserAuth(auth);
            } catch (error: any) {
                setError(error);
            } finally {
                setIsLoading(false);
            }
        };

        fetchUser();
    }, []);

    return { user, setUser, isLoading, error, userAuth };
}