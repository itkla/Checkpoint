import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow
} from '@/components/ui/table';

interface SecurityEvent {
    id: string;
    eventType: 'login' | 'passkey_register' | 'passkey_delete' | 'password_change';
    device?: string;
    browser?: string;
    ip?: string;
    location?: string;
    timestamp: string;
}

export function SecurityLog({ open, onOpenChange }: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const [events, setEvents] = useState<SecurityEvent[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        if (open) {
            // Fetch security events
            // fetchSecurityEvents();
        }
    }, [open]);

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-4xl">
                <DialogHeader>
                    <DialogTitle>セキュリティログ</DialogTitle>
                </DialogHeader>

                <div className="space-y-4">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>日時</TableHead>
                                <TableHead>イベント</TableHead>
                                <TableHead>デバイス</TableHead>
                                <TableHead>場所</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {events.map((event) => (
                                <TableRow key={event.id}>
                                    <TableCell>
                                        {new Date(event.timestamp).toLocaleString('ja-JP')}
                                    </TableCell>
                                    <TableCell>
                                        {event.eventType === 'login' && 'ログイン'}
                                        {event.eventType === 'passkey_register' && 'パスキー登録'}
                                        {event.eventType === 'passkey_delete' && 'パスキー削除'}
                                        {event.eventType === 'password_change' && 'パスワード変更'}
                                    </TableCell>
                                    <TableCell>
                                        {event.device} / {event.browser}
                                    </TableCell>
                                    <TableCell>
                                        {event.location} ({event.ip})
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </div>
            </DialogContent>
        </Dialog>
    );
}