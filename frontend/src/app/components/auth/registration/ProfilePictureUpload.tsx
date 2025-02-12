import React, { useRef } from 'react';
import { UserIcon, PlusIcon } from '@heroicons/react/24/solid';

interface ProfilePictureUploadProps {
    preview?: string;
    onFileSelect: (file: File) => void;
}

export function ProfilePictureUpload({ preview, onFileSelect }: ProfilePictureUploadProps) {
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleClick = () => {
        // Trigger file selection
        fileInputRef.current?.click();
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            onFileSelect(e.target.files[0]);
        }
    };

    return (
        <div className="flex justify-center mb-6">
            <div
                onClick={handleClick}
                className="cursor-pointer w-24 h-24 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden hover:bg-gray-300 transition-colors"
            >
                {preview ? (
                    <img src={preview} alt="Profile preview" className="object-cover w-full h-full" />
                ) : (
                    <UserIcon className="text-gray-400 h-8 w-8" />
                )}
            </div>
            <input
                type="file"
                accept="image/*"
                ref={fileInputRef}
                onChange={handleChange}
                className="hidden"
            />
        </div>
    );
}
