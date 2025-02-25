"use client"

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
    Squares2X2Icon,
    UserIcon,
    Cog6ToothIcon,
    CreditCardIcon,
} from '@heroicons/react/24/outline'
import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
} from '@/components/ui/sidebar'

const menuItems = [
    { href: '/dashboard', icon: Squares2X2Icon, label: 'ホーム' },
    { href: '/dashboard/users', icon: UserIcon, label: 'ユーザー' },
    { href: '/dashboard/settings', icon: Cog6ToothIcon, label: '設定' },
    { href: '/dashboard/billing', icon: CreditCardIcon, label: '請求' },
]

export default function DashboardSidebar() {
    const pathname = usePathname()

    return (
        <Sidebar>
            <SidebarContent>
                <SidebarGroup>
                    <SidebarGroupLabel>Application</SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {menuItems.map((item) => (
                                <SidebarMenuItem key={item.label}>
                                    <SidebarMenuButton asChild>
                                        <a href={item.href}>
                                            <item.icon />
                                            <span>{item.label}</span>
                                        </a>
                                    </SidebarMenuButton>
                                </SidebarMenuItem>
                            ))}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>
            </SidebarContent>
        </Sidebar>
    )
}
