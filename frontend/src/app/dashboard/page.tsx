// frontend/src/pages/dashboard.tsx

"use client";

import { useEffect, useState, ChangeEvent, FormEvent } from 'react';
import { useRouter } from 'next/navigation';

interface User {
    id: number;
    name: string;
    email: string;
    role: string;
    profilePicture: string;
    // Add any other fields as needed.
}

export default function Dashboard() {
    const router = useRouter();
    const [currentUser, setCurrentUser] = useState<User | null>(null);
    const [users, setUsers] = useState<User[]>([]);
    const [selectedUser, setSelectedUser] = useState<User | null>(null);
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isDropdownOpen, setIsDropdownOpen] = useState(false);

    // For demonstration, we use dummy data.
    // Replace these useEffect calls with your API calls (and include your auth logic).
    useEffect(() => {
        // Simulate fetching the current (logged in) user.
        setCurrentUser({
            id: 99,
            name: 'Current User',
            email: 'current@example.com',
            role: 'admin',
            profilePicture: 'https://via.placeholder.com/50',
        });

        // Simulate fetching the users list.
        setUsers([
            {
                id: 1,
                name: 'Alice Smith',
                email: 'alice@example.com',
                role: 'admin',
                profilePicture: 'https://via.placeholder.com/50',
            },
            {
                id: 2,
                name: 'Bob Johnson',
                email: 'bob@example.com',
                role: 'user',
                profilePicture: 'https://via.placeholder.com/50',
            },
            {
                id: 3,
                name: 'Charlie Brown',
                email: 'charlie@example.com',
                role: 'user',
                profilePicture: 'https://via.placeholder.com/50',
            },
        ]);
    }, []);

    // Handlers for modal display
    const openModal = (user: User) => {
        setSelectedUser(user);
        setIsModalOpen(true);
    };

    const closeModal = () => {
        setSelectedUser(null);
        setIsModalOpen(false);
    };

    // Handler for logout
    const handleLogout = () => {
        localStorage.removeItem('token');
        router.push('/login');
    };

    // Stub functions for Delete, Edit, Merge
    const handleDelete = (user: User) => {
        // Replace with your API call
        console.log('Delete', user);
    };

    const handleEdit = (user: User) => {
        // Replace with your API call or modal for editing.
        console.log('Edit', user);
    };

    const handleMerge = (user: User) => {
        // Replace with your API call or merge modal.
        console.log('Merge', user);
    };

    return (
        <div className="flex h-screen bg-gray-100">
            {/* Sidebar */}
            <aside className="w-64 bg-white shadow-md p-6">
                <h2 className="text-2xl font-bold mb-8 text-indigo-600">Dashboard</h2>
                <nav>
                    <ul>
                        <li className="mb-4">
                            <a href="#" className="text-gray-700 hover:text-indigo-600">
                                Home
                            </a>
                        </li>
                        <li className="mb-4">
                            <a href="#" className="text-gray-700 hover:text-indigo-600">
                                Users
                            </a>
                        </li>
                        <li className="mb-4">
                            <a href="#" className="text-gray-700 hover:text-indigo-600">
                                Settings
                            </a>
                        </li>
                    </ul>
                </nav>
            </aside>

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col">
                {/* Top Navbar */}
                <header className="flex justify-between items-center bg-white shadow px-6 py-4">
                    <div className="flex items-center">
                        {/* Logo */}
                        <div className="text-2xl font-bold text-indigo-600">Logo</div>
                    </div>
                    <div className="relative">
                        <img
                            src={currentUser?.profilePicture || 'https://via.placeholder.com/50'}
                            alt="Profile"
                            className="w-10 h-10 rounded-full cursor-pointer"
                            onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                        />
                        {isDropdownOpen && (
                            <div className="absolute right-0 mt-2 w-48 bg-white border rounded-md shadow-lg z-20">
                                <a
                                    href="#"
                                    className="block px-4 py-2 text-gray-800 hover:bg-gray-100"
                                >
                                    User Settings
                                </a>
                                <button
                                    onClick={handleLogout}
                                    className="w-full text-left px-4 py-2 text-gray-800 hover:bg-gray-100"
                                >
                                    Logout
                                </button>
                            </div>
                        )}
                    </div>
                </header>

                {/* Main Section */}
                <main className="p-6 overflow-auto">
                    <h1 className="text-3xl font-bold mb-6">Users</h1>
                    <div className="bg-white rounded-lg shadow overflow-hidden">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Profile
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Email
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        User ID
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Role
                                    </th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {users.map((user) => (
                                    <tr
                                        key={user.id}
                                        className="hover:bg-gray-50 cursor-pointer"
                                        onClick={() => openModal(user)}
                                    >
                                        <td className="px-6 py-4 flex items-center space-x-4">
                                            <img
                                                src={user.profilePicture}
                                                alt={user.name}
                                                className="w-10 h-10 rounded-full"
                                            />
                                            <span className="text-gray-900 font-medium">
                                                {user.name}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-gray-600">
                                            {user.email}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-gray-600">
                                            {user.id}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-gray-600">
                                            {user.role}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <div className="flex space-x-2">
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleDelete(user);
                                                    }}
                                                    className="text-red-600 hover:text-red-800"
                                                >
                                                    Delete
                                                </button>
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleEdit(user);
                                                    }}
                                                    className="text-blue-600 hover:text-blue-800"
                                                >
                                                    Edit
                                                </button>
                                                <button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        handleMerge(user);
                                                    }}
                                                    className="text-green-600 hover:text-green-800"
                                                >
                                                    Merge
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </main>

                {/* Modal for User Details */}
                {isModalOpen && selectedUser && (
                    <div className="fixed inset-0 flex items-center justify-center z-30">
                        {/* Modal overlay */}
                        <div
                            className="fixed inset-0 bg-black opacity-50"
                            onClick={closeModal}
                        ></div>
                        {/* Modal content */}
                        <div className="bg-white rounded-lg shadow-lg z-40 max-w-lg w-full p-6">
                            <div className="flex items-center space-x-4 mb-4">
                                <img
                                    src={selectedUser.profilePicture}
                                    alt={selectedUser.name}
                                    className="w-16 h-16 rounded-full"
                                />
                                <div>
                                    <h2 className="text-2xl font-bold">{selectedUser.name}</h2>
                                    <p className="text-gray-600">{selectedUser.email}</p>
                                </div>
                            </div>
                            <div className="space-y-2">
                                <p>
                                    <span className="font-semibold">User ID:</span>{' '}
                                    {selectedUser.id}
                                </p>
                                <p>
                                    <span className="font-semibold">Role:</span>{' '}
                                    {selectedUser.role}
                                </p>
                                {/* Render any other user fields here */}
                            </div>
                            <div className="mt-6 flex justify-end">
                                <button
                                    onClick={closeModal}
                                    className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
