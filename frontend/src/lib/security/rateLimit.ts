import { createHash } from 'crypto';

interface RateLimitOptions {
    windowMs: number;
    max: number;
}

class RateLimiter {
    private cache: Map<string, { count: number; resetTime: number }>;
    private options: RateLimitOptions;

    constructor(options: RateLimitOptions) {
        this.cache = new Map();
        this.options = options;
    }

    async check(identifier: string): Promise<boolean> {
        const hash = createHash('sha256').update(identifier).digest('hex');
        const now = Date.now();
        const record = this.cache.get(hash);

        if (!record || now > record.resetTime) {
            this.cache.set(hash, {
                count: 1,
                resetTime: now + this.options.windowMs,
            });
            return true;
        }

        if (record.count >= this.options.max) {
            return false;
        }

        record.count += 1;
        return true;
    }
}

export const rateLimiter = new RateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
});