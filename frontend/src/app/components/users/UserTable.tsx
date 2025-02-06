import { useState } from 'react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { Checkbox } from '@/components/ui/checkbox';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { EllipsisVerticalIcon } from '@heroicons/react/24/solid';
import { Button } from '@/components/ui/button';
import { UserDetailDialog } from './UserDetailDialog';
import type { User } from '@/app/types/user';

interface UserTableProps {
    users: User[];
    onEdit: (user: User) => void;
    onDelete: (user: User) => void;
}

export default function UserTable({ users, onEdit, onDelete }: UserTableProps) {
    const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const [showDetails, setShowDetails] = useState(false);

    const toggleUser = (email: string) => {
        setSelectedUsers(prev =>
            prev.includes(email)
                ? prev.filter(e => e !== email)
                : [...prev, email]
        );
    };

    const handleRowClick = (user: User) => {
        setSelectedUser(user);
        setShowDetails(true);
    };

    return (
        <>
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="w-12">
                            <Checkbox />
                        </TableHead>
                        <TableHead>名前</TableHead>
                        <TableHead>メールアドレス</TableHead>
                        <TableHead>役割</TableHead>
                        <TableHead>状態</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {users.map((user) => (
                        <TableRow
                            key={user.email}
                            onClick={() => handleRowClick(user)}
                            className="cursor-pointer"
                        >
                            <TableCell onClick={(e) => e.stopPropagation()}>
                                <Checkbox
                                    checked={selectedUsers.includes(user.email)}
                                    onCheckedChange={() => toggleUser(user.email)}
                                />
                            </TableCell>
                            <TableCell className="flex items-center">
                                <img
                                    src={user.profile_pic}
                                    alt={user.name}
                                    className="w-6 h-6 rounded-full mr-2"
                                />
                                {user.name}
                            </TableCell>
                            <TableCell>{user.email}</TableCell>
                            <TableCell>{user.role}</TableCell>
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
                                        <DropdownMenuItem onClick={() => onEdit(user)}>
                                            編集
                                        </DropdownMenuItem>
                                        <DropdownMenuItem
                                            onClick={() => onDelete(user)}
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
                onEdit={onEdit}
            />
        </>
    );
}