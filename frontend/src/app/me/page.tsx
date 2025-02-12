'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api-client';
import { User } from '@/app/types/user';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { EditProfileDialog } from '@/app/components/account/EditProfileDialog';
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';
import { jwtDecode } from 'jwt-decode';
import { AvatarUpload } from '@/app/components/account/AvatarUpload';
import { PasswordChangeDialog } from '@/app/components/account/PasswordChangeDialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { SessionManager } from '@/app/components/account/SessionManager';
import { ActivityLog } from '@/app/components/account/ActivityLog';
import { DeleteAccount } from '@/app/components/account/DeleteAccount';
import { PasskeyManager } from '@/app/components/account/PasskeyManager';
import { SSOConnections } from '@/app/components/account/SSOConnections';
import { SignOutButton } from '@/app/components/SignOutButton';
import { Avatar } from '@/components/ui/avatar';
import { 
    LockClosedIcon,
    UserIcon,
    ChartBarSquareIcon,
    PhoneIcon,
    EnvelopeIcon,
} from '@heroicons/react/24/outline';

export default function AccountPage() {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [showEditDialog, setShowEditDialog] = useState(false);
    const [showPasswordDialog, setShowPasswordDialog] = useState(false);
    const [showSessions, setShowSessions] = useState(false);
    const [showActivity, setShowActivity] = useState(false);
    const [showDeleteAccount, setShowDeleteAccount] = useState(false);
    const [showPasskeyManager, setShowPasskeyManager] = useState(false);
    const { toast } = useToast();

    useEffect(() => {
        const fetchUserData = async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    throw new Error('No token found');
                }

                const decoded = jwtDecode<{ userId: string }>(token);
                const userData = await api.users.getUser(decoded.userId);
                console.log('User data:', userData);
                setUser(userData);
                console.log('User:', user);
            } catch (error) {
                toast({
                    title: "エラー",
                    description: "ユーザー情報の取得に失敗しました",
                    variant: "destructive",
                });
            } finally {
                setIsLoading(false);
            }
        };

        fetchUserData();
    }, [toast]);

    if (isLoading) {
        return (
            <div className="flex justify-center items-center min-h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
            </div>
        );
    }

    if (!user) {
        return (
            <div className="flex justify-center items-center min-h-screen">
                <p>ユーザー情報が見つかりません</p>
            </div>
        );
    }

    return (
        <div className="container mx-auto py-8 px-4">
            <div className="max-w-4xl mx-auto">
                <Tabs defaultValue="profile" className="space-y-6">
                    <div className="flex justify-between items-center">
                        <div className="flex-1">
                            <TabsList>
                                <TabsTrigger value="profile">プロフィール</TabsTrigger>
                                <TabsTrigger value="security">セキュリティ</TabsTrigger>
                                <TabsTrigger value="activity">アクティビティ</TabsTrigger>
                            </TabsList>
                        </div>
                        <div className="flex flex-1 justify-end items-center">
                            <SignOutButton />
                        </div>
                    </div>

                    <TabsContent value="profile">
                        <Card>
                            <CardHeader>
                                <div className="flex justify-between items-center">
                                    <div>
                                        <CardTitle>プロフィール情報</CardTitle>
                                        <CardDescription>個人情報の確認と編集</CardDescription>
                                    </div>
                                    <Button onClick={() => setShowEditDialog(true)}>
                                        編集
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="flex items-center space-x-4">
                                    <AvatarUpload
                                        currentAvatar={user.profile?.profile_pic}
                                        userId={user.id}
                                        onAvatarUpdate={(url) => setUser({ ...user, profile: { ...user.profile, profile_pic: url } })}
                                    />
                                    <div>
                                        <h2 className="text-2xl font-bold">
                                            {user.profile?.first_name || ''} {user.profile?.last_name || ''}
                                        </h2>
                                        {/* <p className="text-md text-gray-800">{user.first_name} {user.last_name}</p> */}
                                        <p className="text-gray-700">{user.email}</p>
                                        <p className="text-xs text-gray-500">ID: {user.id}</p>
                                    </div>
                                </div>
                                <div className="flex items-center space-x-4">
                                    <h2 className="text-xl font-bold">個人情報</h2>
                                    <div className="flex items-left space-x-2 rounded-lg bg-gray-100 p-2 flex-col">
                                        <p className="text-md text-gray-700">
                                            <PhoneIcon className="inline-block mr-2 w-5 h-5 align-middle" />
                                            {user.profile?.phone || '未設定'}
                                        </p>
                                        <p className="text-md text-gray-700">
                                            <EnvelopeIcon className="inline-block mr-2 w-5 h-5 align-middle" />
                                            {typeof user.profile?.address === 'object'
                                                ? `${user.profile?.address.street || ''} ${user.profile?.address.city || ''}`.trim() || '未設定'
                                                : user.profile?.address || '未設定'}
                                        </p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </TabsContent>

                    <TabsContent value="security">
                        <Card>
                            <CardHeader>
                                <CardTitle>セキュリティ設定</CardTitle>
                                <CardDescription>認証方法とセキュリティの管理</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                <div className="flex justify-between items-center">
                                    <div>
                                        <h3 className="font-medium">パスワード</h3>
                                        <p className="text-sm text-gray-500">
                                            前回の変更: {user.password_changed_at ?
                                                new Date(user.password_changed_at).toLocaleDateString('ja-JP') :
                                                '不明'}
                                        </p>
                                    </div>
                                    <Button onClick={() => setShowPasswordDialog(true)}>
                                        パスワードを変更
                                    </Button>
                                </div>

                                <div className="flex justify-between items-center">
                                    <div>
                                        <h3 className="font-medium">パスキー</h3>
                                        <p className="text-sm text-gray-500">
                                            生体認証やデバイスのセキュリティ機能を使用
                                        </p>
                                    </div>
                                    <Button
                                        variant="outline"
                                        onClick={() => setShowPasskeyManager(true)}
                                    >
                                        パスキーを管理
                                    </Button>
                                </div>

                                <div className="pt-6 border-t">
                                    <SSOConnections />
                                </div>

                                <div className="flex justify-between items-center">
                                    <div>
                                        <h3 className="font-medium">2要素認証</h3>
                                        <p className="text-sm text-gray-500">
                                            {user.two_factor_enabled ?
                                                '有効' :
                                                'アカウントの安全性を高めるために2要素認証の設定をお勧めします'}
                                        </p>
                                    </div>
                                    <Button variant="outline">
                                        {user.two_factor_enabled ? '設定を変更' : '設定'}
                                    </Button>
                                </div>

                                <div className="flex justify-between items-center">
                                    <div>
                                        <h3 className="font-medium">ログインデバイス</h3>
                                        <p className="text-sm text-gray-500">
                                            現在のアクティブなセッションを管理
                                        </p>
                                    </div>
                                    <Button variant="outline">
                                        デバイスを管理
                                    </Button>
                                </div>
                                <div className="flex justify-between items-center">
                                    <div>
                                        <h3 className="font-medium">セッション管理</h3>
                                        <p className="text-sm text-gray-500">
                                            アクティブなデバイスとセッションを確認
                                        </p>
                                    </div>
                                    <Button
                                        variant="outline"
                                        onClick={() => setShowSessions(true)}
                                    >
                                        セッションを管理
                                    </Button>
                                </div>

                                <div className="pt-6 border-t">
                                    <h3 className="font-medium text-red-600">危険な操作</h3>
                                    <p className="text-sm text-gray-500 mt-1">
                                        一度削除したアカウントは復元できません
                                    </p>
                                    <Button
                                        variant="destructive"
                                        className="mt-4"
                                        onClick={() => setShowDeleteAccount(true)}
                                    >
                                        アカウントを削除
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    </TabsContent>

                    <TabsContent value="activity">
                        <Card>
                            <CardHeader>
                                <CardTitle>アカウントアクティビティ</CardTitle>
                                <CardDescription>
                                    最近のログインとセキュリティイベント
                                </CardDescription>
                            </CardHeader>
                            <CardContent>
                                <Button
                                    variant="outline"
                                    onClick={() => setShowActivity(true)}
                                >
                                    すべてのアクティビティを表示
                                </Button>
                            </CardContent>
                        </Card>
                    </TabsContent >
                </Tabs >

                <EditProfileDialog
                    user={user}
                    open={showEditDialog}
                    onOpenChange={setShowEditDialog}
                    onUserUpdate={(updatedUser) => setUser(updatedUser)}
                />

                <PasswordChangeDialog
                    open={showPasswordDialog}
                    onOpenChange={setShowPasswordDialog}
                />
                <SessionManager
                    open={showSessions}
                    onOpenChange={setShowSessions}
                />

                <ActivityLog
                    open={showActivity}
                    onOpenChange={setShowActivity}
                />

                <DeleteAccount
                    email={user.email}
                    open={showDeleteAccount}
                    id={user.id}
                    onOpenChange={setShowDeleteAccount}
                />

                <PasskeyManager
                    open={showPasskeyManager}
                    onOpenChange={setShowPasskeyManager}
                />
            </div >
        </div >
    );
}