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
import { RoleBadge } from '@/app/components/RoleBadge';
import { TwoFactorSetup } from '@/app/components/auth/TwoFactorSetup';

export default function AccountPage() {
    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [showEditDialog, setShowEditDialog] = useState(false);
    const [showPasswordDialog, setShowPasswordDialog] = useState(false);
    const [showSessions, setShowSessions] = useState(false);
    const [showActivity, setShowActivity] = useState(false);
    const [showDeleteAccount, setShowDeleteAccount] = useState(false);
    const [showPasskeyManager, setShowPasskeyManager] = useState(false);
    const [show2FASetup, setShow2FASetup] = useState(false);
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
                            <CardContent className="space-y-8">
                                {/* Profile Header */}
                                <div className="flex items-start space-x-6">
                                    <AvatarUpload
                                        currentAvatar={user.profile?.profile_pic}
                                        userId={user.id}
                                        onAvatarUpdate={(url) => setUser({ ...user, profile: { ...user.profile, profile_pic: url } })}
                                    />
                                    <div className="flex-1">
                                        <div className="flex items-center space-x-3">
                                            <h2 className="text-2xl font-bold">
                                                {user.profile?.first_name || ''} {user.profile?.last_name || ''}
                                            </h2>
                                            <div className="flex space-x-1">
                                                {user.role?.split(',').map((role, index) => (
                                                    <RoleBadge key={index} role={role.trim()} />
                                                ))}
                                            </div>
                                        </div>
                                        <p className="text-gray-600">{user.email}</p>
                                        <p className="text-sm text-gray-500 mt-1">ID: {user.id}</p>
                                    </div>
                                </div>

                                {/* Contact Information */}
                                <div className="space-y-4">
                                    <h3 className="text-lg font-semibold border-b pb-2">連絡先情報</h3>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div>
                                            <p className="text-sm text-gray-500">メールアドレス</p>
                                            <p className="flex items-center mt-1">
                                                <EnvelopeIcon className="w-5 h-5 text-gray-400 mr-2" />
                                                {user.email}
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm text-gray-500">電話番号</p>
                                            <p className="flex items-center mt-1">
                                                <PhoneIcon className="w-5 h-5 text-gray-400 mr-2" />
                                                {user.profile?.phone || '未設定'}
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                <div className="flex flex-row justify-between">
                                    {/* Address Information */}
                                {user.profile?.address && (
                                    <div className="space-y-4">
                                        <h3 className="text-lg font-semibold border-b pb-2">住所</h3>
                                        <div className="bg-gray-50 rounded-lg p-4">
                                            <div className="space-y-2">
                                                {user.profile.address.street && (
                                                    <p className="text-gray-700">{user.profile.address.street}</p>
                                                )}
                                                {user.profile.address.street2 && (
                                                    <p className="text-gray-700">{user.profile.address.street2}</p>
                                                )}
                                                <p className="text-gray-700">
                                                    {[
                                                        user.profile.address.city,
                                                        user.profile.address.state,
                                                        user.profile.address.zip
                                                    ].filter(Boolean).join(', ')}
                                                </p>
                                                {user.profile.address.country && (
                                                    <p className="text-gray-700">{user.profile.address.country}</p>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Account Information */}
                                <div className="space-y-4">
                                    <h3 className="text-lg font-semibold border-b pb-2">アカウント情報</h3>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div>
                                            <p className="text-sm text-gray-500">登録日</p>
                                            <p className="mt-1">
                                                {user.created_at
                                                    ? new Date(user.created_at).toLocaleDateString('ja-JP', {
                                                        year: 'numeric',
                                                        month: 'long',
                                                        day: 'numeric'
                                                    })
                                                    : '不明'
                                                }
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-sm text-gray-500">最終ログイン</p>
                                            <p className="mt-1">
                                                {user.last_login
                                                    ? new Date(user.last_login).toLocaleDateString('ja-JP', {
                                                        year: 'numeric',
                                                        month: 'long',
                                                        day: 'numeric',
                                                        hour: '2-digit',
                                                        minute: '2-digit'
                                                    })
                                                    : '不明'
                                                }
                                            </p>
                                        </div>
                                    </div>
                                </div>
                                
                                {/* Permissions */}
                                {user.permissions && (
                                    <div className="space-y-4">
                                        <h3 className="text-lg font-semibold border-b pb-2">権限</h3>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            <div>
                                                <p className="text-sm text-gray-500">権限</p>
                                                <ul className="mt-1">
                                                    {user.permissions.map((permission, index) => (
                                                        <li key={index} className="flex items-center space-x-2">
                                                            <LockClosedIcon className="w-5 h-5 text-gray-400" />
                                                            <span>{permission}</span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                )}
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
                                    <Button variant="outline" onClick={() => setShow2FASetup(true)}>
                                        {show2FASetup ? '設定中…' : '2FA設定'}
                                    </Button>
                                    {show2FASetup && (
                                    <TwoFactorSetup
                                        isOpen={show2FASetup}
                                        onClose={() => setShow2FASetup(false)}
                                        is2FAEnabled={!!user.two_factor_enabled}
                                        onComplete={() => {
                                            // Optionally update user state or show a success toast
                                            setShow2FASetup(false);
                                        }}
                                    />
                                )}
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