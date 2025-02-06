"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
    Squares2X2Icon,
    UserIcon,
    Cog6ToothIcon,
    CreditCardIcon
} from '@heroicons/react/24/outline';

const menuItems = [
    { href: '/dashboard', icon: Squares2X2Icon, label: 'ホーム' },
    { href: '/dashboard/users', icon: UserIcon, label: 'ユーザー' },
    { href: '/dashboard/settings', icon: Cog6ToothIcon, label: '設定' },
    { href: '/dashboard/billing', icon: CreditCardIcon, label: '請求' },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="bg-white p-6 hidden md:block w-64">
            <nav className="flex flex-col space-y-4">
                {menuItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={`text-gray-600 hover:text-blue-500 transition-colors font-medium flex items-center space-x-2 ${isActive ? 'text-blue-500' : ''
                                }`}
                        >
                            <Icon className="w-5 h-5" />
                            <span>{item.label}</span>
                        </Link>
                    );
                })}
            </nav>
        </aside>
    );
}