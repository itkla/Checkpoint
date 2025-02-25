import {
    UsersIcon,
    CurrencyDollarIcon,
    ChartBarIcon,
    ArrowTrendingUpIcon
} from '@heroicons/react/24/outline';

interface StatCardProps {
    title: string;
    value: string;
    trend: string;
    icon: React.ElementType;
}

const StatCard = ({ title, value, trend, icon: Icon }: StatCardProps) => (
    <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between">
            <div>
                <p className="text-sm text-gray-600">{title}</p>
                <p className="text-2xl font-semibold mt-1">{value}</p>
                <p className="text-sm text-green-600 flex items-center mt-1">
                    <ArrowTrendingUpIcon className="w-4 h-4 mr-1" />
                    {trend}
                </p>
            </div>
            <div className="bg-blue-50 p-3 rounded-full">
                <Icon className="w-6 h-6 text-blue-500" />
            </div>
        </div>
    </div>
);

export default function DashboardPage() {
    const stats = [
        {
            title: "総ユーザー数",
            value: "12,345",
            trend: "2.5% 増加",
            icon: UsersIcon
        },
        {
            title: "月間収益",
            value: "¥2,456,789",
            trend: "4.7% 増加",
            icon: CurrencyDollarIcon
        },
        {
            title: "アクティブユーザー",
            value: "8,765",
            trend: "1.2% 増加",
            icon: ChartBarIcon
        },
    ];

    return (
        <div>
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-700 mb-2">ホーム</h1>
                <p className="text-gray-500">システムの概要と主要な指標を確認できます。</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                {stats.map((stat) => (
                    <StatCard key={stat.title} {...stat} />
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white rounded-lg shadow p-6">
                    <h2 className="text-lg font-semibold mb-4">最近のアクティビティ</h2>
                </div>
                <div className="bg-white rounded-lg shadow p-6">
                    <h2 className="text-lg font-semibold mb-4">重要な通知</h2>
                </div>
            </div>
        </div>
    );
}