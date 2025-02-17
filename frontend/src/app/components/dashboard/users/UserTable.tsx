// components/users/UserTable.tsx
import { useState } from 'react';
import { useQuery, useMutation, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api } from '@/lib/api-client';
import type { User } from '@/app/types/user';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Checkbox } from '@/components/ui/checkbox';
import { Button } from '@/components/ui/button';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { EllipsisVerticalIcon } from '@heroicons/react/24/solid';
import { useToast } from '@/hooks/use-toast';
import { UserDetailDialog } from './UserDetailDialog';

interface TableProps {
    onUserSelect?: (user: User) => void;
}

export default function UserTable() {
    const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [showDetails, setShowDetails] = useState(false);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const { toast } = useToast();
    const queryClient = new QueryClient();

    // Fetch users
    const { data: users = [], isLoading, error } = useQuery({
        queryKey: ['users'],
        queryFn: () => api.users.getUsers(),
    });

    // Delete mutation
    const deleteMutation = useMutation({
        mutationFn: (userId: string) => api.users.deleteUser(userId),
        onSuccess: () => {
            // queryClient is now available from context
            queryClient.invalidateQueries({ queryKey: ['users'] });
            toast({ title: "成功", description: "ユーザーを削除しました" });
        },
        onError: () => {
            toast({
                title: "エラー",
                description: "ユーザーの削除に失敗しました",
                variant: "destructive"
            });
        },
    });

    // Update mutation
    const updateMutation = useMutation({
        mutationFn: (user: User) => api.users.updateUser(user.id, user),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['users'] });
            toast({
                title: "成功",
                description: "ユーザー情報を更新しました",
            });
        },
        onError: () => {
            toast({
                title: "エラー",
                description: "ユーザーの更新に失敗しました",
                variant: "destructive",
            });
        },
    });

    const handleEdit = (user: User) => {
        updateMutation.mutate(user);
    };

    const handleDelete = (user: User) => {
        deleteMutation.mutate(user.id);
    };

    const toggleUser = (userId: string) => {
        setSelectedUsers(prev =>
            prev.includes(userId)
                ? prev.filter(id => id !== userId)
                : [...prev, userId]
        );
    };

    const handleRowClick = (user: User) => {
        setSelectedUser(user);
        setShowDetails(true);
    };

    if (isLoading) {
        return <div className="flex justify-center p-4">Loading...</div>;
    }

    if (error) {
        return (
            <div className="text-red-500 p-4">
                エラーが発生しました
            </div>
        );
    }

    return (
        <>
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="w-12">
                            <Checkbox
                                checked={selectedUsers.length === users.length}
                                onCheckedChange={(checked) => {
                                    if (checked) {
                                        setSelectedUsers(users.map(user => user.id));
                                    } else {
                                        setSelectedUsers([]);
                                    }
                                }}
                            />
                        </TableHead>
                        <TableHead>名前</TableHead>
                        <TableHead>メールアドレス</TableHead>
                        <TableHead>役割</TableHead>
                        <TableHead>状態</TableHead>
                        <TableHead className="text-right">アクション</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {users.map((user) => (
                        <TableRow
                            key={user.id}
                            onClick={() => handleRowClick(user)}
                            className="cursor-pointer"
                        >
                            <TableCell onClick={(e) => e.stopPropagation()}>
                                <Checkbox
                                    checked={selectedUsers.includes(user.id)}
                                    onCheckedChange={() => toggleUser(user.id)}
                                />
                            </TableCell>
                            <TableCell className="flex items-center">
                                <img
                                    src={user.profile?.profile_pic || "https://placehold.co/50"}
                                    alt={user.profile?.first_name || user.email}
                                    className="w-6 h-6 rounded-full mr-2"
                                />
                                {user.profile?.first_name || user.email}
                            </TableCell>
                            <TableCell>{user.email}</TableCell>
                            <TableCell>{user.role || 'N/A'}</TableCell>
                            <TableCell>
                                {user.active ? (
                                    <span className="text-green-600 font-medium">アクティブ</span>
                                ) : (
                                    <span className="text-red-600 font-medium">非アクティブ</span>
                                )}
                            </TableCell>
                            <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                                <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                        <Button variant="ghost" className="h-8 w-8 p-0">
                                            <EllipsisVerticalIcon className="h-4 w-4" />
                                        </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end">
                                        <DropdownMenuItem
                                            onClick={() => handleEdit(user)}
                                            disabled={updateMutation.isPending}
                                        >
                                            編集
                                        </DropdownMenuItem>
                                        <DropdownMenuItem
                                            onClick={() => handleDelete(user)}
                                            disabled={deleteMutation.isPending}
                                            className="text-red-600"
                                        >
                                            削除
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>

            <UserDetailDialog
                user={selectedUser}
                open={showDetails}
                onOpenChange={setShowDetails}
                onEdit={handleEdit}
            />
        </>
    );
}