'use client';

import { useState } from 'react';
import { ArrowPathIcon } from '@heroicons/react/24/solid';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { QueryClientProvider, useQuery } from '@tanstack/react-query';
import { queryClient } from '@/lib/query-client';
import UserTable from '@/app/components/dashboard/users/UserTable';
import type { User } from '@/app/types/user';
import { api } from '@/lib/api-client';
import { UserDetailDialog } from '@/app/components/dashboard/users/UserDetailDialog';
import { EditUserDialog } from '@/app/components/dashboard/users/EditUserDialog';

export default function UsersPageWrapper() {
    return (
        <QueryClientProvider client={queryClient}>
            <UsersContent />
        </QueryClientProvider>
    );
}

function UsersContent() {
    const [searchQuery, setSearchQuery] = useState('');
    const [showDetails, setShowDetails] = useState(false);
    const [showEditDialog, setShowEditDialog] = useState(false);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);

    // Use React Query to fetch users with proper data extraction
    const { data, isLoading, refetch } = useQuery({
        queryKey: ['users'],
        queryFn: async () => {
            const response = await api.users.getUsers();
            return response.users || []; // Extract just the users array
        },
    });

    const users = data || [];

    const filteredUsers = Array.isArray(users) ? users.filter(user =>
        (user.profile?.first_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        (user.email || '').toLowerCase().includes(searchQuery.toLowerCase())
    ) : [];

    const handleEdit = (user: User) => {
        setSelectedUser(user);
        setShowDetails(false); // Ensure details dialog is closed
        setShowEditDialog(true);
    };

    const handleDelete = async (user: User) => {
        if (confirm(`本当に ${user.profile?.first_name || user.email} を削除しますか?`)) {
            try {
                await api.users.deleteUser(user.id);
                refetch();
            } catch (error) {
                console.error('Failed to delete user:', error);
            }
        }
    };

    const handleDetails = (user: User) => {
        setSelectedUser(user);
        setShowEditDialog(false); // Ensure edit dialog is closed
        setShowDetails(true);
    };

    const handleRefresh = () => {
        refetch();
    };

    const handleSaveUser = async (updatedUser: User) => {
        try {
            await api.users.updateUser(updatedUser.id, updatedUser);
            refetch();
            setShowEditDialog(false);
        } catch (error) {
            console.error('Failed to update user:', error);
        }
    };

    return (
        <div>
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-700 mb-2">ユーザー管理</h1>
                <p className="text-gray-500">ユーザーの追加、編集、削除を行います。</p>
            </div>

            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center space-x-4">
                    <Button>+ ユーザー</Button>
                    <Button variant="secondary" onClick={handleRefresh}>
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

            {isLoading ? (
                <div>Loading users...</div>
            ) : (
                <UserTable
                    users={filteredUsers}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                    onDetails={handleDetails}
                />
            )}

            {selectedUser && (
                <>
                    <UserDetailDialog 
                        user={selectedUser} 
                        open={showDetails} 
                        onOpenChange={(open) => {
                            setShowDetails(open);
                            if (!open) setSelectedUser(null); // Clear selected user when closing
                        }}
                        onEdit={() => {
                            setShowDetails(false);
                            setShowEditDialog(true);
                        }}
                    />

                    <EditUserDialog
                        user={selectedUser}
                        open={showEditDialog}
                        onOpenChange={(open) => {
                            setShowEditDialog(open);
                            if (!open) setSelectedUser(null); // Clear selected user when closing
                        }}
                        onSave={handleSaveUser}
                    />
                </>
            )}
        </div>
    );
}