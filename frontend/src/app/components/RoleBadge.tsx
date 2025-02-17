// components/RoleBadge.tsx
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import {
    UserIcon,
    ShieldCheckIcon,
    PencilSquareIcon,
    EyeIcon,
    LifebuoyIcon
} from '@heroicons/react/24/outline';

const roleConfig: Record<string, { icon: React.ComponentType<React.SVGProps<SVGSVGElement>>, color: string, description: string }> = {
    'admin': {
        icon: ShieldCheckIcon,
        color: 'text-red-500',
        description: '管理者'
    },
    'support': {
        icon: LifebuoyIcon,
        color: 'text-blue-500',
        description: '編集者'
    },
    'viewer': {
        icon: EyeIcon,
        color: 'text-green-500',
        description: '閲覧者'
    },
    'default': {
        icon: UserIcon,
        color: 'text-gray-500',
        description: 'ユーザー'
    }
};

export function RoleBadge({ role }: { role: string }) {
    const config = roleConfig[role.toLowerCase()] || roleConfig.default;
    const Icon = config.icon;

    return (
        <TooltipProvider>
            <Tooltip>
                <TooltipTrigger>
                    <div className={`inline-flex items-center justify-center p-1 rounded-full bg-gray-100 ${config.color}`}>
                        <Icon className="w-4 h-4" />
                    </div>
                </TooltipTrigger>
                <TooltipContent>
                    <p>{config.description}</p>
                </TooltipContent>
            </Tooltip>
        </TooltipProvider>
    );
}