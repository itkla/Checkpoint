import { Button } from '@/components/ui/button';

export default function Navbar() {
    return (
        <header className="bg-white shadow-lg px-8 py-4 flex items-center justify-between">
            {/* <div className="text-2xl font-semibold text-gray-600">[brand]</div> */}
            <img src="/logo.svg" className="w-48"></img>
            <div className="flex items-center space-x-8">
                <span className="text-gray-600">[user]</span>
                <Button
                    variant="ghost"
                    className="text-blue-500 font-medium hover:text-blue-600"
                >
                    ログアウト
                </Button>
            </div>
        </header>
    );
}
