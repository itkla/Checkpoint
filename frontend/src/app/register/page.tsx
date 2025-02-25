'use client';

import { RegistrationForm } from '@/app/components/auth/RegistrationForm';
import { motion, AnimatePresence } from 'framer-motion';

export default function RegisterPage() {
    return (
        <div className="flex justify-center items-center min-h-screen bg-gray-100 p-4">
            <div className="w-full max-w-5xl">
                <AnimatePresence mode="wait">
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.2 }}
                    >
                        <RegistrationForm />
                    </motion.div>
                </AnimatePresence>
            </div>
        </div>
    );
}