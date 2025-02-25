import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
    CalendarIcon, 
    PhoneIcon,
    MapPinIcon,
    CakeIcon,
    KeyIcon,
    UserIcon,
    ShieldCheckIcon,
    ClockIcon
} from "@heroicons/react/24/outline";
import { User } from "@/app/types/user";
import { format } from "date-fns";

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

    // Format date if available
    const formatDate = (dateString?: string) => {
        if (!dateString) return '未設定';
        try {
            return format(new Date(dateString), 'yyyy/MM/dd');
        } catch (e) {
            return dateString;
        }
    };

    // Format the full address into a single string
    const formatAddress = () => {
        const address = user.profile?.address;
        if (!address) return '未設定';
        
        const parts = [
            address.country,
            address.state,
            address.city,
            address.zip,
            address.street,
            address.street2
        ].filter(Boolean);
        
        return parts.length > 0 ? parts.join(', ') : '未設定';
    };

    const fullName = [user.profile?.first_name, user.profile?.last_name]
        .filter(Boolean)
        .join(' ') || user.email?.split('@')[0] || 'ユーザー';

    // Get initials for avatar fallback
    const getInitials = () => {
        const first = user.profile?.first_name?.charAt(0) || '';
        const last = user.profile?.last_name?.charAt(0) || '';
        return (first + last).toUpperCase() || user.email?.charAt(0).toUpperCase() || 'U';
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
                <DialogHeader className="pb-2">
                    <div className="flex items-center space-x-4">
                        <Avatar className="h-16 w-16">
                            <AvatarImage src={user.profile?.profile_picture} alt={fullName} />
                            <AvatarFallback className="text-lg font-medium bg-primary/10 text-primary">
                                {getInitials()}
                            </AvatarFallback>
                        </Avatar>
                        <div>
                            <DialogTitle className="text-2xl font-bold">{fullName}</DialogTitle>
                            <p className="text-sm text-muted-foreground">{user.email}</p>
                            <Badge variant={user.role === "admin" ? "default" : "outline"} className="mt-1">
                                {user.role || 'ユーザー'}
                            </Badge>
                        </div>
                    </div>
                </DialogHeader>

                <Separator className="my-2" />

                <div className="space-y-6 py-2">
                    {/* Personal Info Section */}
                    <div>
                        <h3 className="font-semibold text-sm text-muted-foreground mb-3 flex items-center">
                            <UserIcon className="w-4 h-4 mr-2" />
                            個人情報
                        </h3>
                        
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="flex items-center space-x-3">
                                <CakeIcon className="w-4 h-4 text-muted-foreground" />
                                <div>
                                    <p className="text-xs text-muted-foreground">誕生日</p>
                                    <p className="text-sm">{formatDate(user.profile?.dateOfBirth)}</p>
                                </div>
                            </div>
                            
                            <div className="flex items-center space-x-3">
                                <PhoneIcon className="w-4 h-4 text-muted-foreground" />
                                <div>
                                    <p className="text-xs text-muted-foreground">電話番号</p>
                                    <p className="text-sm">{user.profile?.phone || '未設定'}</p>
                                </div>
                            </div>
                            
                            <div className="flex space-x-3 col-span-2">
                                <MapPinIcon className="w-4 h-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                                <div>
                                    <p className="text-xs text-muted-foreground mb-1">住所</p>
                                    {user.profile?.address ? (
                                        <div className="text-sm space-y-0.5">
                                            {user.profile.address.street && <p>{user.profile.address.street}</p>}
                                            {user.profile.address.street2 && <p>{user.profile.address.street2}</p>}
                                            <p>
                                                {[
                                                    user.profile.address.city,
                                                    user.profile.address.state,
                                                    user.profile.address.zip
                                                ].filter(Boolean).join(', ')}
                                            </p>
                                            {user.profile.address.country && <p>{user.profile.address.country}</p>}
                                        </div>
                                    ) : (
                                        <p className="text-sm">未設定</p>
                                    )}
                                </div>
                            </div>
                            
                            <div className="flex items-center space-x-3">
                                <ClockIcon className="w-4 h-4 text-muted-foreground" />
                                <div>
                                    <p className="text-xs text-muted-foreground">登録日</p>
                                    <p className="text-sm">{formatDate(user.created_at)}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <Separator />

                    {/* Security Section */}
                    <div>
                        <h3 className="font-semibold text-sm text-muted-foreground mb-3 flex items-center">
                            <ShieldCheckIcon className="w-4 h-4 mr-2" />
                            セキュリティ情報
                        </h3>
                        
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="flex items-center space-x-3">
                                <KeyIcon className="w-4 h-4 text-muted-foreground" />
                                <div>
                                    <p className="text-xs text-muted-foreground">2FA認証</p>
                                    <Badge 
                                        variant="outline" 
                                        className={user.two_factor_enabled ? "bg-green-50 text-green-600 border-green-200" : "bg-red-50 text-red-600 border-red-200"}
                                    >
                                        {user.two_factor_enabled ? '有効' : '無効'}
                                    </Badge>
                                </div>
                            </div>
                            
                            {user.permissions && user.permissions.length > 0 && (
                                <div className="col-span-2">
                                    <p className="text-xs text-muted-foreground mb-1">権限</p>
                                    <div className="flex flex-wrap gap-1.5">
                                        {user.permissions.map((permission) => (
                                            <Badge
                                                key={permission}
                                                variant="secondary"
                                                className="text-xs font-normal"
                                            >
                                                {permission}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                <DialogFooter className="sm:justify-between gap-2">
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