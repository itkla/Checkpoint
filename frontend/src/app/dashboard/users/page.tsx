'use client';

import { useState } from 'react';
import { ArrowPathIcon } from '@heroicons/react/24/solid';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from '@/lib/query-client';
import UserTable from '@/app/components/dashboard/users/UserTable';
import { Dialog } from '@/components/ui/dialog';
import type { User } from '@/app/types/user';
import { authApi, userApi } from '@/lib/api-client';

const all_users = await userApi.getUsers();

export default function UsersPage() {
    const [searchQuery, setSearchQuery] = useState('');
    const [showDetails, setShowDetails] = useState(false);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);

    const filteredUsers = all_users.filter(user =>
        (user.profile?.first_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (user.email || '').toLowerCase().includes(searchQuery.toLowerCase())
    );

    const handleEdit = (user: User) => {
        // Implement edit functionality
        console.log('Edit user:', user);
    };

    const handleDelete = (user: User) => {
        // Implement delete functionality
        console.log('Delete user:', user);
    };

    const handleDetails = (user: User) => {
        setSelectedUser(user);
        setShowDetails(true);
    };

    return (
        <QueryClientProvider client={queryClient}>
            <div>
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-gray-700 mb-2">ユーザー管理</h1>
                    <p className="text-gray-500">ユーザーの追加、編集、削除を行います。</p>
                </div>

                <div className="flex items-center justify-between mb-8">
                    <div className="flex items-center space-x-4">
                        <Button>+ ユーザー</Button>
                        <Button variant="secondary">
                            <ArrowPathIcon className="h-4 w-4" />
                        </Button>
                    </div>
                    <div className="relative w-1/3">
                        <Input
                            type="text"
                            placeholder="検索..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                    </div>
                </div>

                <UserTable
                    users={filteredUsers}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                    onDetails={handleDetails}
                />

                <Dialog open={showDetails} onOpenChange={setShowDetails}>
                    {selectedUser && (
                        <div className="p-6">
                            <h2 className="text-2xl font-bold mb-4">{selectedUser.name}</h2>
                            <div className="space-y-2">
                                <p><span className="font-medium">メールアドレス:</span> {selectedUser.email}</p>
                                <p><span className="font-medium">役割:</span> {selectedUser.role}</p>
                                <p><span className="font-medium">状態:</span> {selectedUser.active ? 'アクティブ' : '非アクティブ'}</p>
                            </div>
                        </div>
                    )}
                </Dialog>
            </div>
        </QueryClientProvider>
    );
}