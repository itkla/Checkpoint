import { ReactNode } from 'react';
import Navbar from '@/app/components/dashboard/DashboardNavbar';
import Sidebar from '@/app/components/dashboard/DashboardSidebar';

export default function DashboardLayout({
    children,
}: {
    children: ReactNode;
}) {
    return (
        <div className="min-h-screen flex flex-col">
            <Navbar />
            <div className="flex flex-1">
                <Sidebar />
                <main className="flex-1 bg-white p-8">
                    {children}
                </main>
            </div>
        </div>
    );
}