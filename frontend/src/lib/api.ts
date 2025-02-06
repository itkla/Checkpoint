import {User} from '@/app/types/user';

const API_BASE = '/api';

export async function fetchUsers(page: number, limit: number) {
    const response = await fetch(
        `${API_BASE}/users?page=${page}&limit=${limit}`
    );
    if (!response.ok) throw new Error('Failed to fetch users');
    return response.json();
}

export async function updateUser(user: User) {
    const response = await fetch(`${API_BASE}/users/${user.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(user),
    });
    if (!response.ok) throw new Error('Failed to update user');
    return response.json();
}

export async function deleteUser(userId: string) {
    const response = await fetch(`${API_BASE}/users/${userId}`, {
        method: 'DELETE',
    });
    if (!response.ok) throw new Error('Failed to delete user');
    return response.json();
}