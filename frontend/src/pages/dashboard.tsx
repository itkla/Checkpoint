import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

export default function Dashboard() {
    const [user, setUser] = useState(null);
    const router = useRouter();

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            router.push('/login');
            return;
        }

        fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/user`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        })
            .then((res) => res.json())
            .then(setUser)
            .catch(() => {
                localStorage.removeItem('token');
                router.push('/login');
            });
    }, []);

    if (!user) {
        return <div>Loading...</div>;
    }

    return (
        <div className="min-h-screen bg-gray-100">
            <nav className="bg-white shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between h-16">
                        <div className="flex items-center">
                            <h1 className="text-xl font-semibold">Checkpoint Dashboard</h1>
                        </div>
                        <div className="flex items-center">
                            <button
                                onClick={() => {
                                    localStorage.removeItem('token');
                                    router.push('/login');
                                }}
                                className="ml-4 px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700"
                            >
                                Sign out
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                <div className="px-4 py-6 sm:px-0">
                    <div className="border-4 border-dashed border-gray-200 rounded-lg h-96">
                        <div className="p-4">
                            <h2 className="text-lg font-semibold">Welcome, {user.name || user.email}!</h2>
                            {/* Add your dashboard content here */}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}