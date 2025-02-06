import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CalendarIcon, PhoneIcon, BuildingOfficeIcon } from "@heroicons/react/24/outline";
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

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-2xl">
                <DialogHeader>
                    <div className="flex items-center space-x-4">
                        <img
                            src={user.profile_pic}
                            alt={user.name}
                            className="w-16 h-16 rounded-full"
                        />
                        <div>
                            <DialogTitle className="text-2xl font-bold">{user.name}</DialogTitle>
                            <p className="text-gray-500">{user.email}</p>
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
                                    <BuildingOfficeIcon className="w-5 h-5 mr-2" />
                                    <span>部署: {user.department || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <PhoneIcon className="w-5 h-5 mr-2" />
                                    <span>電話: {user.phone || '未設定'}</span>
                                </div>
                                <div className="flex items-center text-gray-600">
                                    <CalendarIcon className="w-5 h-5 mr-2" />
                                    <span>登録日: {user.joined_date || '不明'}</span>
                                </div>
                            </div>

                            <div className="pt-4">
                                <h4 className="font-medium text-gray-900 mb-2">ステータス</h4>
                                <Badge
                                    variant={user.active ? "success" : "destructive"}
                                    className="text-xs"
                                >
                                    {user.active ? 'アクティブ' : '非アクティブ'}
                                </Badge>
                            </div>
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

                            <div className="pt-4">
                                <h4 className="font-medium text-gray-900 mb-2">最終ログイン</h4>
                                <span className="text-gray-600">{user.last_login || '記録なし'}</span>
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