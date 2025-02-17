import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
    CalendarIcon, 
    PhoneIcon,
    BuildingOfficeIcon,
    CakeIcon
} from "@heroicons/react/24/outline";
import { User } from "@/app/types/user";

interface UserDetailsDialogProps {
    user: User | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onEdit: (user: User) => void;
}

export function UserDetailDialog({
    user,
    open,
    onOpenChange,
    onEdit
}: UserDetailsDialogProps) {
    if (!user) return null;
    console.log(user);

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-2xl">
                <DialogHeader>
                    <div className="flex items-center space-x-4">
                        <img
                            src={user.profile?.profile_pic}
                            alt={user.profile?.first_name}
                            className="w-16 h-16 rounded-full"
                        />
                        <div>
                            <DialogTitle className="text-2xl font-bold">{user.profile?.first_name}</DialogTitle>
                            <p className="text-gray-500">{user.email}</p>
                            <p className="text-xs text-gray-300">{user.id}</p>
                        </div>
                    </div>
                </DialogHeader>

                <div className="py-4">
                    <div className="grid grid-cols-2 gap-6">
                        {/* Left column */}
                        <div className="space-y-4">
                            <h3 className="font-semibold text-gray-900 border-b pb-2">基本情報</h3>

                            <div className="space-y-2">
                                <div className="flex items-center text-gray-600">
                                    <CakeIcon className="w-5 h-5 mr-2" />
                                    <span>誕生日: {user.profile?.dateOfBirth || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <PhoneIcon className="w-5 h-5 mr-2" />
                                    <span>電話: {user.profile?.phone || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <CalendarIcon className="w-5 h-5 mr-2" />
                                    <span>登録日: {user.created_at || '不明'}</span>
                                </div>
                            </div>

                            <h3 className="font-semibold text-gray-900 border-b pb-2">住所</h3>

                            <div className="space-y-2">
                                <div className="flex items-center text-gray-600">
                                    {/* <BuildingOfficeIcon className="w-5 h-5 mr-2" /> */}
                                    <span>{user.profile?.address?.country || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    {/* <PhoneIcon className="w-5 h-5 mr-2" /> */}
                                    <span>{user.profile?.address?.zip || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <span>{user.profile?.address?.state || '不明'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <span>{user.profile?.address?.city || '不明'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <span>{user.profile?.address?.street || '不明'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <span>{user.profile?.address?.street2 || '不明'}</span>
                                </div>
                            </div>

                            {/* <div className="pt-4">
                                <h4 className="font-medium text-gray-900 mb-2">ステータス</h4>
                                <Badge
                                    variant={user.active ? "default" : "destructive"}
                                    className="text-xs"
                                >
                                    {user.active ? 'アクティブ' : '非アクティブ'}
                                </Badge>
                            </div> */}
                        </div>

                        {/* Right column */}
                        <div className="space-y-4">
                            <h3 className="font-semibold text-gray-900 border-b pb-2">アクセス権限</h3>

                            <div>
                                <div className="mb-2">
                                    <span className="font-medium">役割:</span>{' '}
                                    <Badge variant="outline" className="ml-2">
                                        {user.role}
                                    </Badge>
                                </div>

                                <div className="space-y-2">
                                    <h4 className="text-sm font-medium text-gray-900">権限:</h4>
                                    <div className="flex flex-wrap gap-2">
                                        {user.permissions?.map((permission) => (
                                            <Badge
                                                key={permission}
                                                variant="secondary"
                                                className="text-xs"
                                            >
                                                {permission}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            </div>
                            
                            <h3 className="font-semibold text-gray-900 border-b pb-2">セキュリティ</h3>
                            <div className="">
                                {/* <h4 className="font-medium text-gray-900 mb-2">セキュリティ</h4>
                                <span className="text-gray-600">{user.last_login || '記録なし'}</span> */}
                                {/* <span className="font-medium text-gray-900">2FA </span> */}
                                <span className="text-gray-900">2FA: 
                                    <Badge
                                        variant="outline"
                                        className={`ml-2 ${
                                            user.two_factor_enabled
                                                ? "text-green-500 border-green-500"
                                                : "text-red-500 border-red-500"
                                        }`}
                                    >
                                        {user.two_factor_enabled ? '有効' : '無効'}
                                    </Badge>
                                </span>
                                {/* <span className="text-gray-900">Password last changed: {user.password_changed_at || '記録なし'}</span> */}
                            </div>
                        </div>
                    </div>
                </div>

                <DialogFooter className="flex justify-between">
                    <Button variant="outline" onClick={() => onOpenChange(false)}>
                        閉じる
                    </Button>
                    <Button onClick={() => onEdit(user)}>
                        編集
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

export default UserDetailDialog;