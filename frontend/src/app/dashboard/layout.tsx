import { ReactNode } from 'react'
import Navbar from '@/app/components/dashboard/DashboardNavbar'
import DashboardSidebar from '@/app/components/dashboard/DashboardSidebar'
import { SidebarProvider, SidebarTrigger } from '@/components/ui/sidebar';
import {AppSidebar} from '@/app/components/dashboard/app-sidebar';
import { cookies } from 'next/headers';

export default async function DashboardLayout({ children }: { children: ReactNode }) {
    const token = (await cookies()).get('checkpoint_jwt')?.value || '';
    // const { user, setUser, isLoading, error, userAuth } = useUser();
    return (
        // <div className="min-h-screen flex flex-col">
        //     <Navbar />
        //     <div className="flex flex-1">
        //         <DashboardSidebar />
        //         <main className="flex-1 bg-white p-8">
        //             {children}
        //         </main>
        //     </div>
        // </div>
        <SidebarProvider style={{
                    "--sidebar-width": "16rem",
                    "--sidebar-bg": "#f9fafb",
                    "--sidebar-text-color": "#374151",
                    "--sidebar-text-color-hover": "#161e2e",
                    "--sidebar-border-color": "#d2d6dc",
                    "--sidebar-shadow": "0 4px 12px rgba(0, 0, 0, 0.1)",
                    "--sidebar-border-width": "1px",
                    "--sidebar-border-style": "solid",
                    "--sidebar-border-radius": "0.5rem",
                    "--sidebar-transition": "transform 0.2s ease-in-out",
                    "--sidebar-z-index": "100",
                    "--sidebar-trigger-z-index": "101",
                    "--sidebar-trigger-bg": "#f9fafb",
                    "--sidebar-trigger-color": "#374151",
                    "--sidebar-trigger-color-hover": "#161e2e",
                    "--sidebar-trigger-border-color": "#d2d6dc",
                    "--sidebar-trigger-border-width": "1px",
                    "--sidebar-trigger-border-style": "solid",
                    "--sidebar-trigger-border-radius": "0.5rem",
                    "--sidebar-trigger-shadow": "0 4px 12px rgba(0, 0, 0, 0.1)",
                    "--sidebar-trigger-padding": "0.5rem",
                    "--sidebar-trigger-transition": "background-color 0.2s ease-in-out",
                } as React.CSSProperties & Record<string, string>}>
            <AppSidebar />
            <main className="flex-1 bg-white p-8">
                <SidebarTrigger />
                {children}
            </main>
        </SidebarProvider>
    )
}
