import { useState } from 'react';
import { Table, TableBody, TableCell, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { EllipsisVerticalIcon } from '@heroicons/react/24/solid';
import type { User } from '@/app/types/user';

export default function UserTable({ 
    users, 
    onEdit, 
    onDelete, 
    onDetails 
}: {
    users: User[];
    onEdit: (user: User) => void;
    onDelete: (user: User) => void;
    onDetails: (user: User) => void;
}) {
    const handleRowClick = (user: User) => {
        onDetails(user);
    };

    const handleEdit = (user: User) => {
        onEdit(user);
    };

    const handleDelete = (user: User) => {
        onDelete(user);
    };

    return (
        <Table>
            <TableHeader>
                <TableRow>
                    <TableCell>名前</TableCell>
                    <TableCell>メールアドレス</TableCell>
                    <TableCell>ID</TableCell>
                    <TableCell>役割</TableCell>
                    <TableCell>状態</TableCell>
                    <TableCell className="text-right">アクション</TableCell>
                </TableRow>
            </TableHeader>
            <TableBody>
                {Array.isArray(users) && users.map((user) => (
                    <TableRow
                        key={user.id}
                        onClick={() => handleRowClick(user)}
                        className="cursor-pointer"
                    >
                        <TableCell className="flex items-center">
                            <img
                                src={user.profile?.profile_pic || "https://placehold.co/50"}
                                alt={user.profile?.first_name || user.email}
                                className="w-6 h-6 rounded-full mr-2"
                            />
                            {user.profile?.first_name || user.email} {user.profile?.last_name}
                        </TableCell>
                        <TableCell>{user.email}</TableCell>
                        <TableCell>{user.id}</TableCell>
                        <TableCell>{user.role || 'N/A'}</TableCell>
                        <TableCell>
                            {user.active !== undefined ? (
                                user.active ? (
                                    <span className="text-green-600 font-medium">アクティブ</span>
                                ) : (
                                    <span className="text-red-600 font-medium">非アクティブ</span>
                                )
                            ) : (
                                <span className="text-gray-500">不明</span>
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
                                    <DropdownMenuItem onClick={() => handleEdit(user)}>
                                        編集
                                    </DropdownMenuItem>
                                    <DropdownMenuItem 
                                        onClick={() => handleDelete(user)}
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
    );
}