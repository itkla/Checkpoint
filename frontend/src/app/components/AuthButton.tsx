import React from 'react';

interface AuthButtonProps {
    onClick?: () => void;
    children: React.ReactNode;
    primary?: boolean;
    type?: "button" | "submit" | "reset";
    disabled?: boolean;
}

const AuthButton: React.FC<AuthButtonProps> = ({ onClick, children, primary = false }) => {
    const baseClasses = "w-full font-bold py-3 px-6 rounded mb-2";
    const colorClasses = primary
        ? "bg-blue-500 hover:bg-blue-700 text-white transition-colors"
        : "bg-gray-400 hover:bg-gray-500 text-white transition-colors";

    return (
        <button
            onClick={onClick}
            className={`${baseClasses} ${colorClasses}`}
        >
            {children}
        </button>
    );
};

export default AuthButton;