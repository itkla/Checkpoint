import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Toaster } from '@/components/ui/toaster';
import { AlertTriangleIcon } from "lucide-react";
import "./globals.css";

const geistSans = Geist({
    variable: "--font-geist-sans",
    subsets: ["latin"],
});

const geistMono = Geist_Mono({
    variable: "--font-geist-mono",
    subsets: ["latin"],
});

export const metadata: Metadata = {
    title: "Checkpoint",
    description: "Secure authentication for the modern age",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="light">
            <body
                className={`${geistSans.variable} ${geistMono.variable} antialiased`}
            >
                <div className="fixed top-0 left-0 right-0 bg-amber-500 text-white py-2 text-center text-sm font-medium z-50">
                    <AlertTriangleIcon className="inline-block w-4 h-4 mr-1" />
                    この製品は開発中であり、すべての機能がまだ利用できるわけではありません
                    <AlertTriangleIcon className="inline-block w-4 h-4 ml-1" />
                </div>
                {children}
                <Toaster />
            </body>
        </html>
    );
}
