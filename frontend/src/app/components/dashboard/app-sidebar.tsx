'use client';

import { Calendar, CreditCard, Home, Inbox, Search, Settings, Users, LogOut, UserCog } from "lucide-react";
import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarHeader,
    SidebarFooter,
    SidebarTrigger,
    SidebarSeparator,
    useSidebar
} from "@/components/ui/sidebar";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { User2 } from "lucide-react";
import { ChevronUp } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { useUser } from "@/hooks/useUser";
import { SignOutButton, SignOut } from "../SignOutButton";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { cn } from "@/lib/utils";

const year = new Date().getFullYear();

const items = [
    {
        title: "Home",
        url: "/dashboard",
        icon: Home,
    },
    {
        title: "Users",
        url: "/dashboard/users",
        icon: Users,
    },
    {
        title: "Billing",
        url: "/dashboard/billing",
        icon: CreditCard,
    },
    {
        title: "Settings",
        url: "/dashboard/settings",
        icon: Settings,
    },
];

export function AppSidebar() {
    const { user, setUser, userAuth, isLoading, error } = useUser();
    const pathname = usePathname();
    const { state } = useSidebar();
    const isCollapsed = state === "collapsed";
    const getIsActive = (itemUrl: string) => {
        // Exact match
        if (pathname === itemUrl) {
            return true;
        }
        if (itemUrl === "/dashboard") {
            return pathname === "/dashboard";
        }
        if (pathname.startsWith(itemUrl + "/") || pathname === itemUrl) {
            return true;
        }

        return false;
    };

    return (
        <Sidebar collapsible="icon" className="border-r border-border">
            <div className="flex items-center px-4 py-3 justify-between">
                <SidebarHeader className="flex-1">
                    {isCollapsed ? (
                        <div className="flex justify-center">
                            <img src="/logo-icon.svg" alt="Logo" className="h-8 w-8" />
                        </div>
                    ) : (
                        <img src="/logo.svg" alt="Logo" className="w-36" />
                    )}
                </SidebarHeader>
                {/* <SidebarTrigger /> */}
            </div>

            <SidebarSeparator />

            <SidebarContent className="pt-2">
                <SidebarGroup>
                    <SidebarGroupLabel>Platform</SidebarGroupLabel>
                    <SidebarGroupContent>
                        <SidebarMenu>
                            {items.map((item) => {
                                const isActive = getIsActive(item.url);
                                return (
                                    <SidebarMenuItem key={item.title}>
                                        <SidebarMenuButton
                                            asChild
                                            isActive={isActive}
                                            className={cn(
                                                "transition-colors",
                                                isActive ? "bg-muted" : ""
                                            )}
                                        >
                                            <Link href={item.url}>
                                                <item.icon className={isActive ? "text-primary" : ""} />
                                                <span className={isActive ? "font-medium text-primary" : ""}>
                                                    {item.title}
                                                </span>
                                            </Link>
                                        </SidebarMenuButton>
                                    </SidebarMenuItem>
                                );
                            })}
                        </SidebarMenu>
                    </SidebarGroupContent>
                </SidebarGroup>
            </SidebarContent>

            <SidebarFooter>
                <SidebarMenu>
                    <SidebarMenuItem>
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <SidebarMenuButton className="bg-muted/50 hover:bg-muted">
                                    <Avatar className="h-8 w-8 rounded-full bg-neutral-500">
                                        <AvatarImage src={user?.profile?.profile_pic} />
                                        <AvatarFallback>{user?.profile?.first_name?.charAt(0) || "U"}</AvatarFallback>
                                    </Avatar>
                                    <span>{user?.profile?.first_name} {user?.profile?.last_name}</span>
                                    <ChevronUp className="ml-auto h-4 w-4 opacity-70" />
                                </SidebarMenuButton>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent
                                align="start"
                                side="top"
                                className="w-[--radix-popper-anchor-width]"
                            >
                                <DropdownMenuItem>
                                    <Link href="/me" className="flex w-full items-center">
                                        <UserCog className="mr-2 h-4 w-4" />
                                        Account
                                    </Link>
                                </DropdownMenuItem>
                                <DropdownMenuItem>
                                    <Link href="/dashboard/billing" className="flex w-full items-center">
                                        <CreditCard className="mr-2 h-4 w-4" />
                                        Billing
                                    </Link>
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem className="text-destructive focus:text-destructive">
                                    <Link onClick={() => SignOut()} className="flex w-full items-center" href="#">
                                        <LogOut className="mr-2 h-4 w-4" /> ログアウト
                                    </Link>
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </SidebarMenuItem>
                </SidebarMenu>
                <SidebarSeparator />
                <div className="p-3 text-xs text-muted-foreground text-center">
                    {!isCollapsed && <p>Checkpoint © {year}</p>}
                </div>
            </SidebarFooter>
        </Sidebar>
    );
}