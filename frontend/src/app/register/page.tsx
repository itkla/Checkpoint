'use client';

import { RegistrationForm } from '@/app/components/auth/RegistrationForm';
import { motion, AnimatePresence } from 'framer-motion';

export default function RegisterPage() {
    return (
        <div className="container flex justify-center items-center min-h-screen">
            <div className="bg-white drop-shadow-lg w-full max-w-md p-8 py-10 rounded-[5%]">
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