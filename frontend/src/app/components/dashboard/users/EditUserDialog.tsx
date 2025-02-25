'use client';

import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import type { User } from "@/app/types/user";

interface EditUserDialogProps {
    user: User | null;
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSave: (user: User) => void;
}

export function EditUserDialog({
    user,
    open,
    onOpenChange,
    onSave,
}: EditUserDialogProps) {
    const [formData, setFormData] = useState<Partial<User>>({});
    const [isSubmitting, setIsSubmitting] = useState(false);
    
    // Update form data when user changes or dialog opens
    useEffect(() => {
        if (user) {
            setFormData(user);
        }
    }, [user, open]);
    
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!user) return;
        
        setIsSubmitting(true);
        try {
            await onSave({ ...user, ...formData });
            onOpenChange(false);
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-xl">
                <DialogHeader>
                    <DialogTitle>ユーザー編集</DialogTitle>
                </DialogHeader>

                <form onSubmit={handleSubmit} className="space-y-6">
                    {/* Personal Info Section */}
                    <div>
                        <h3 className="font-semibold text-sm text-muted-foreground mb-3 flex items-center">
                            個人情報
                        </h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="first_name">名</Label>
                                <Input
                                    id="first_name"
                                    value={formData.profile?.first_name || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { ...formData.profile, first_name: e.target.value } 
                                    })}
                                    required
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="last_name">姓</Label>
                                <Input
                                    id="last_name"
                                    value={formData.profile?.last_name || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { ...formData.profile, last_name: e.target.value } 
                                    })}
                                    required
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="email">メールアドレス</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    value={formData.email || ''}
                                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                    required
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="phone">電話番号</Label>
                                <Input
                                    id="phone"
                                    type="tel"
                                    value={formData.profile?.phone || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { ...formData.profile, phone: e.target.value } 
                                    })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="dateOfBirth">誕生日</Label>
                                <Input
                                    id="dateOfBirth"
                                    type="date"
                                    value={formData.profile?.dateOfBirth ? new Date(formData.profile.dateOfBirth).toISOString().split('T')[0] : ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { ...formData.profile, dateOfBirth: new Date(e.target.value).toISOString() } 
                                    })}
                                />
                            </div>
                        </div>
                    </div>

                    <Separator />

                    {/* User Status Section */}
                    <div>
                        <h3 className="font-semibold text-sm text-muted-foreground mb-3 flex items-center">
                            ユーザー状態
                        </h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="department">部署</Label>
                                <Input
                                    id="department"
                                    value={formData.department || ''}
                                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="role">役割</Label>
                                <Select
                                    value={formData.role || ''}
                                    onValueChange={(value) => setFormData({ ...formData, role: value })}
                                >
                                    <SelectTrigger>
                                        <SelectValue placeholder="役割を選択" />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="Admin">管理者</SelectItem>
                                        <SelectItem value="Editor">編集者</SelectItem>
                                        <SelectItem value="Viewer">閲覧者</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>

                            <div className="space-y-2">
                                <Label>アクティブ状態</Label>
                                <div className="flex items-center space-x-2">
                                    <Switch
                                        checked={!!formData.active}
                                        onCheckedChange={(checked) =>
                                            setFormData({ ...formData, active: checked })
                                        }
                                    />
                                    <Label>{formData.active ? 'アクティブ' : '非アクティブ'}</Label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <Separator />

                    {/* Address Section */}
                    <div>
                        <h3 className="font-semibold text-sm text-muted-foreground mb-3 flex items-center">
                            住所
                        </h3>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="col-span-2 space-y-2">
                                <Label htmlFor="address_street"></Label>
                                <Input
                                    id="address_street"
                                    value={formData.profile?.address?.street || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, street: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>

                            <div className="col-span-2 space-y-2">
                                <Label htmlFor="address_street2">部屋番号・建物名</Label>
                                <Input
                                    id="address_street2"
                                    value={formData.profile?.address?.street2 || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, street2: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="address_city">市区町村</Label>
                                <Input
                                    id="address_city"
                                    value={formData.profile?.address?.city || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, city: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="address_state">都道府県</Label>
                                <Input
                                    id="address_state"
                                    value={formData.profile?.address?.state || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, state: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="address_zip">郵便番号</Label>
                                <Input
                                    id="address_zip"
                                    value={formData.profile?.address?.zip || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, zip: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="address_country">国</Label>
                                <Input
                                    id="address_country"
                                    value={formData.profile?.address?.country || ''}
                                    onChange={(e) => setFormData({ 
                                        ...formData, 
                                        profile: { 
                                            ...formData.profile, 
                                            address: { ...formData.profile?.address, country: e.target.value } 
                                        } 
                                    })}
                                />
                            </div>
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            type="button"
                            variant="outline"
                            onClick={() => onOpenChange(false)}
                            disabled={isSubmitting}
                        >
                            キャンセル
                        </Button>
                        <Button type="submit" disabled={isSubmitting}>
                            {isSubmitting ? '保存中...' : '保存'}
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}