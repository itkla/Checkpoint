import { SignOutButton } from '@/app/components/SignOutButton'

export default function Navbar() {
    return (
        <header className="bg-white shadow-lg px-8 py-4 flex items-center justify-between">
            <img src="/logo.svg" className="w-48" />
            <div className="flex items-center space-x-8">
                <SignOutButton />
            </div>
        </header>
    )
}
