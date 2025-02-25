'use client';

import { useState } from 'react';
import { useUser } from '@/hooks/useUser';
import { useToast } from '@/hooks/use-toast';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Avatar } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { EditProfileDialog } from '@/app/components/account/EditProfileDialog';
import { PasswordChangeDialog } from '@/app/components/account/PasswordChangeDialog';
import { SessionManager } from '@/app/components/account/SessionManager';
import { ActivityLog } from '@/app/components/account/ActivityLog';
import { DeleteAccount } from '@/app/components/account/DeleteAccount';
import { PasskeyManager } from '@/app/components/account/PasskeyManager';
import { SSOConnections } from '@/app/components/account/SSOConnections';
import { SignOutButton } from '@/app/components/SignOutButton';
import { AvatarUpload } from '@/app/components/account/AvatarUpload';
import { RoleBadge } from '@/app/components/RoleBadge';
import { TwoFactorSetup } from '@/app/components/auth/TwoFactorSetup';
import {
  LockClosedIcon,
  UserIcon,
  ChartBarSquareIcon,
  PhoneIcon,
  EnvelopeIcon,
  KeyIcon,
  ShieldCheckIcon,
  DevicePhoneMobileIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';

export default function AccountPage() {
  const { user, isLoading, error, userAuth, setUser } = useUser();
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [showSessions, setShowSessions] = useState(false);
  const [showActivity, setShowActivity] = useState(false);
  const [showDeleteAccount, setShowDeleteAccount] = useState(false);
  const [showPasskeyManager, setShowPasskeyManager] = useState(false);
  const [show2FASetup, setShow2FASetup] = useState(false);
  const { toast } = useToast();
  const router = useRouter();

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
    <div className="bg-white min-h-screen py-10 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8 flex justify-between items-center">
          <h1 className="text-2xl font-semibold text-gray-800">アカウント設定</h1>
          <SignOutButton />
        </div>

        <Tabs defaultValue="profile" className="space-y-8">
          <div className="bg-white rounded-lg p-2 inline-flex">
            <TabsList className="grid grid-cols-3 w-[400px]">
              <TabsTrigger value="profile" className="rounded-md">
                <UserIcon className="w-4 h-4 mr-2" />
                プロフィール
              </TabsTrigger>
              <TabsTrigger value="security" className="rounded-md">
                <ShieldCheckIcon className="w-4 h-4 mr-2" />
                セキュリティ
              </TabsTrigger>
              <TabsTrigger value="activity" className="rounded-md">
                <ChartBarSquareIcon className="w-4 h-4 mr-2" />
                活動ログ
              </TabsTrigger>
            </TabsList>
          </div>

          {/* Profile Tab */}
          <TabsContent value="profile">
            <div className="grid gap-6">
              <Card className="overflow-hidden shadow-sm drop-shadow-lg">
                <div className="py-8 px-6">
                  <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6">
                    <AvatarUpload
                      currentAvatar={user.profile?.profile_pic}
                      userId={user.id}
                      onAvatarUpdate={(url) => setUser({ ...user, profile: { ...user.profile, profile_pic: url } })}
                    />
                    <div className="text-center sm:text-left space-y-2 flex-1">
                      <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                        <h2 className="text-2xl font-bold text-gray-800">
                          {user.profile?.first_name || ''} {user.profile?.last_name || ''}
                        </h2>
                        <div className="flex justify-center sm:justify-start gap-1">
                          {user.role?.split(',').map((role, index) => (
                            <RoleBadge key={index} role={role.trim()} />
                          ))}
                        </div>
                      </div>
                      <p className="text-gray-600">{user.email}</p>
                      <p className="text-xs text-gray-500">アカウント ID: {user.id}</p>
                    </div>
                    <Button 
                      onClick={() => setShowEditDialog(true)}
                      className="sm:self-start"
                      variant="outline"
                    >
                      編集
                    </Button>
                  </div>
                </div>
                
                <CardContent className="p-6">
                  {/* Contact Information */}
                  <div className="mb-8">
                    <h3 className="text-md font-medium text-gray-800 mb-4 flex items-center">
                      <EnvelopeIcon className="h-5 w-5 mr-2 text-blue-500" />
                      連絡先情報
                    </h3>
                    <div className="bg-white rounded-lg border border-gray-100 shadow-sm divide-y divide-gray-100">
                      <div className="flex py-3 px-4">
                        <span className="w-1/3 text-sm text-gray-500">メールアドレス</span>
                        <span className="flex-1 font-medium">{user.email}</span>
                      </div>
                      <div className="flex py-3 px-4">
                        <span className="w-1/3 text-sm text-gray-500">電話番号</span>
                        <span className="flex-1">{user.profile?.phone || '未設定'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    {/* Address */}
                    {user.profile?.address && (
                      <div>
                        <h3 className="text-md font-medium text-gray-800 mb-4 flex items-center">
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                          </svg>
                          住所
                        </h3>
                        <div className="bg-white rounded-lg p-4 border border-gray-100 shadow-sm">
                          <div className="space-y-1">
                            {user.profile.address.zip && (
                              <p className="text-sm font-medium">〒{user.profile.address.zip}</p>
                            )}
                            {user.profile.address.state && (
                              <p>{user.profile.address.state} {user.profile.address.city || ''}</p>
                            )}
                            {user.profile.address.street && (
                              <p>{user.profile.address.street}</p>
                            )}
                            {user.profile.address.street2 && (
                              <p>{user.profile.address.street2}</p>
                            )}
                            {user.profile.address.country && (
                              <p className="text-sm text-gray-500 mt-1">{user.profile.address.country}</p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Account Information */}
                    <div>
                      <h3 className="text-md font-medium text-gray-800 mb-4 flex items-center">
                        <UserIcon className="h-5 w-5 mr-2 text-blue-500" />
                        アカウント情報
                      </h3>
                      <div className="bg-white rounded-lg border border-gray-100 shadow-sm divide-y divide-gray-100">
                        <div className="flex py-3 px-4">
                          <span className="w-1/3 text-sm text-gray-500">登録日</span>
                          <span className="flex-1">
                            {user.created_at
                              ? new Date(user.created_at).toLocaleDateString('ja-JP', {
                                  year: 'numeric',
                                  month: 'long',
                                  day: 'numeric'
                                })
                              : '不明'
                            }
                          </span>
                        </div>
                        <div className="flex py-3 px-4">
                          <span className="w-1/3 text-sm text-gray-500">最終ログイン</span>
                          <span className="flex-1">
                            {user.last_login
                              ? new Date(user.last_login).toLocaleDateString('ja-JP', {
                                  year: 'numeric',
                                  month: 'long',
                                  day: 'numeric'
                                })
                              : '不明'
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                  {user.permissions && user.permissions.length > 0 && (
                    <div className="mt-8">
                      <h3 className="text-md font-medium text-gray-800 mb-4 flex items-center">
                        <LockClosedIcon className="h-5 w-5 mr-2 text-blue-500" />
                        権限
                      </h3>
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                        {user.permissions.map((permission, index) => (
                          <div key={index} className="bg-white border border-gray-100 rounded-md p-2 text-sm flex items-center shadow-sm">
                            <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                            {permission}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security">
            <Card className="shadow-sm">
              <CardHeader className="pb-2">
                <CardTitle>セキュリティ設定</CardTitle>
                <CardDescription>アカウントのセキュリティと認証方法を管理します</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6 pt-4">
                {/* Password Section */}
                <div className="bg-white rounded-lg border border-gray-100 p-5 transition-shadow hover:shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div className="flex items-start space-x-4">
                      <div className="bg-blue-50 p-2 rounded-full">
                        <KeyIcon className="h-5 w-5 text-blue-500" />
                      </div>
                      <div>
                        <h3 className="font-medium mb-1">パスワード</h3>
                        <p className="text-sm text-gray-500">
                          前回の変更: {userAuth?.created_at ? 
                            new Date(userAuth.created_at).toLocaleDateString('ja-JP') : 
                            '不明'}
                        </p>
                      </div>
                    </div>
                    <Button onClick={() => setShowPasswordDialog(true)}>
                      パスワードを変更
                    </Button>
                  </div>
                </div>

                {/* Passkey Section */}
                <div className="bg-white rounded-lg border border-gray-100 p-5 transition-shadow hover:shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div className="flex items-start space-x-4">
                      <div className="bg-green-50 p-2 rounded-full">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                      </div>
                      <div>
                        <h3 className="font-medium mb-1">パスキー</h3>
                        <p className="text-sm text-gray-500">
                          生体認証やデバイスのセキュリティ機能を使用してログイン
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      onClick={() => setShowPasskeyManager(true)}
                    >
                      パスキーを管理
                    </Button>
                  </div>
                </div>

                {/* 2FA Section */}
                <div className="bg-white rounded-lg border border-gray-100 p-5 transition-shadow hover:shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div className="flex items-start space-x-4">
                      <div className="bg-purple-50 p-2 rounded-full">
                        <ShieldCheckIcon className="h-5 w-5 text-purple-500" />
                      </div>
                      <div>
                        <h3 className="font-medium mb-1">2要素認証</h3>
                        <p className="text-sm text-gray-500">
                          {user.two_factor_enabled ? 
                            '有効になっています' : 
                            'アカウントの安全性を高めるために2要素認証の設定をお勧めします'}
                        </p>
                      </div>
                    </div>
                    <Button variant="outline" onClick={() => setShow2FASetup(true)}>
                      {user.two_factor_enabled ? '2FA設定を変更' : '2FA設定'}
                    </Button>
                  </div>
                </div>

                {/* SSO Connections */}
                <div className="bg-white rounded-lg border border-gray-100 p-5 transition-shadow hover:shadow-sm">
                  <h3 className="font-medium mb-3 flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.828 14.828a4 4 0 015.656 0l4 4a4 4 0 01-5.656 5.656l-1.102-1.101" />
                    </svg>
                    外部サービス連携
                  </h3>
                  <SSOConnections />
                </div>

                {/* Session Management */}
                <div className="bg-white rounded-lg border border-gray-100 p-5 transition-shadow hover:shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div className="flex items-start space-x-4">
                      <div className="bg-amber-50 p-2 rounded-full">
                        <DevicePhoneMobileIcon className="h-5 w-5 text-amber-500" />
                      </div>
                      <div>
                        <h3 className="font-medium mb-1">セッション管理</h3>
                        <p className="text-sm text-gray-500">
                          アクティブなデバイスとログインセッションを確認
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      onClick={() => setShowSessions(true)}
                    >
                      セッションを管理
                    </Button>
                  </div>
                </div>

                {/* Danger Zone */}
                <div className="mt-8 pt-6 border-t border-red-100">
                  <div className="bg-red-50 rounded-lg border border-red-100 p-5">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                      <div className="flex items-start space-x-4">
                        <div className="bg-white p-2 rounded-full">
                          <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
                        </div>
                        <div>
                          <h3 className="font-medium text-red-600 mb-1">アカウント削除</h3>
                          <p className="text-sm text-gray-600">
                            一度削除したアカウントは復元できません
                          </p>
                        </div>
                      </div>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setShowDeleteAccount(true)}
                      >
                        アカウントを削除
                      </Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Activity Tab */}
          <TabsContent value="activity">
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle>アカウントアクティビティ</CardTitle>
                <CardDescription>最近のログインとセキュリティイベントの履歴</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-col items-center justify-center py-8">
                  <div className="bg-blue-50 rounded-full p-3 mb-4">
                    <ChartBarSquareIcon className="h-8 w-8 text-blue-500" />
                  </div>
                  <h3 className="text-lg font-medium mb-2">アクティビティログを確認</h3>
                  <p className="text-center text-gray-500 max-w-md mb-6">
                    最近のログイン履歴、デバイス情報、セキュリティイベントなどを確認できます。
                  </p>
                  <Button
                    onClick={() => setShowActivity(true)}
                    className="min-w-[200px]"
                  >
                    すべてのアクティビティを表示
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Dialogs */}
        <EditProfileDialog
          user={user}
          open={showEditDialog}
          onOpenChange={setShowEditDialog}
          onUserUpdate={(updatedUser) => {
            setUser({
              ...user,
              email: updatedUser.email || user.email,
              profile: {
                ...user.profile,
                first_name: updatedUser.profile?.first_name || user.profile?.first_name,
                last_name: updatedUser.profile?.last_name || user.profile?.last_name,
                phone: updatedUser.profile?.phone || user.profile?.phone,
                profile_pic: updatedUser.profile?.profile_pic || user.profile?.profile_pic,
                address: updatedUser.profile?.address || user.profile?.address,
                dateOfBirth: user.profile?.dateOfBirth
              },
              role: user.role,
              permissions: user.permissions,
              last_login: user.last_login,
              created_at: user.created_at,
            });
          }}
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

        {show2FASetup && (
          <TwoFactorSetup
            isOpen={show2FASetup}
            onClose={() => setShow2FASetup(false)}
            is2FAEnabled={!!user.two_factor_enabled}
            onComplete={() => setShow2FASetup(false)}
          />
        )}
      </div>
    </div>
  );
}