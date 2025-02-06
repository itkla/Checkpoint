'use client';

import { useState } from 'react';
import { ArrowPathIcon } from '@heroicons/react/24/solid';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import UserTable from '@/app/components/users/UserTable';
import { Dialog } from '@/components/ui/dialog';
import type { User } from '@/app/types/user';

const mockUsers: User[] = [
    { name: 'John Doe', email: 'john@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Jane Smith', email: 'jane@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Tom Brown', email: 'tom@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Mary Johnson', email: 'mary@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Alice Johnson', email: 'alice.johnson@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Bob Smith', email: 'bob.smith@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Charlie Brown', email: 'charlie.brown@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'David Wilson', email: 'david.wilson@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Eva Green', email: 'eva.green@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Frank White', email: 'frank.white@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Grace Lee', email: 'grace.lee@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Henry King', email: 'henry.king@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Isabella Scott', email: 'isabella.scott@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Jack Davis', email: 'jack.davis@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Karen Martinez', email: 'karen.martinez@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Leo Garcia', email: 'leo.garcia@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Mia Rodriguez', email: 'mia.rodriguez@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Noah Hernandez', email: 'noah.hernandez@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Olivia Clark', email: 'olivia.clark@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Paul Lewis', email: 'paul.lewis@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Quinn Walker', email: 'quinn.walker@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Ruby Hall', email: 'ruby.hall@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Sam Young', email: 'sam.young@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Tina Allen', email: 'tina.allen@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Uma Wright', email: 'uma.wright@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Victor King', email: 'victor.king@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Wendy Scott', email: 'wendy.scott@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Xander Harris', email: 'xander.harris@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Yara Nelson', email: 'yara.nelson@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Zane Carter', email: 'zane.carter@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Amy Mitchell', email: 'amy.mitchell@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Brian Perez', email: 'brian.perez@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Chloe Roberts', email: 'chloe.roberts@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Daniel Turner', email: 'daniel.turner@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Ella Phillips', email: 'ella.phillips@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Finn Campbell', email: 'finn.campbell@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Grace Parker', email: 'grace.parker@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Hannah Evans', email: 'hannah.evans@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Ian Edwards', email: 'ian.edwards@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Jade Collins', email: 'jade.collins@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Kyle Stewart', email: 'kyle.stewart@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Lily Morris', email: 'lily.morris@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Mason Rogers', email: 'mason.rogers@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Nina Reed', email: 'nina.reed@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Oscar Cook', email: 'oscar.cook@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Piper Morgan', email: 'piper.morgan@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Quincy Bell', email: 'quincy.bell@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Riley Murphy', email: 'riley.murphy@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Sophie Bailey', email: 'sophie.bailey@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Tyler Rivera', email: 'tyler.rivera@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Uma Foster', email: 'uma.foster@example.com', role: 'Editor', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Violet Howard', email: 'violet.howard@example.com', role: 'Admin', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Wyatt Ward', email: 'wyatt.ward@example.com', role: 'Viewer', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Xena Brooks', email: 'xena.brooks@example.com', role: 'Editor', active: false, profile_pic: 'https://placehold.co/25' },
                        { name: 'Yvonne Sanders', email: 'yvonne.sanders@example.com', role: 'Admin', active: true, profile_pic: 'https://placehold.co/25' },
                        { name: 'Zachary Price', email: 'zachary.price@example.com', role: 'Viewer', active: false, profile_pic: 'https://placehold.co/25' }
];

export default function UsersPage() {
    const [searchQuery, setSearchQuery] = useState('');
    const [showDetails, setShowDetails] = useState(false);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);

    const filteredUsers = mockUsers.filter(user =>
        user.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.email.toLowerCase().includes(searchQuery.toLowerCase())
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
    );
}