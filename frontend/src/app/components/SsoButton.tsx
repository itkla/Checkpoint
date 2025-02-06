import React from 'react';

interface SsoButtonProps {
    icon: string;
    provider: string;
    onClick: () => void;
}

const LoginButton: React.FC<SsoButtonProps> = ({ icon, provider, onClick }) => {
    return (
        <button
            onClick={onClick}
            className="flex items-center justify-center border border-gray-300 py-2 px-4 rounded shadow-sm hover:bg-gray-100 transition-colors"
        >
            <img src={icon} alt={provider.toLowerCase()} className="w-6 h-6 mr-2 rounded-full" />
            <span>{provider}</span>
        </button>
    );
};

export default LoginButton;