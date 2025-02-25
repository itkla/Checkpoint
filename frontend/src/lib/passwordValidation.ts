export function validatePassword(password: string) {
    return {
        isLongEnough: password.length >= 8,
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password),
        hasDigit: /[0-9]/.test(password),
        hasSpecialChar: /[@$!%*?&_.-/]/.test(password),
    };
}

export function isPasswordValid(password: string): boolean {
    const { isLongEnough, hasUppercase, hasLowercase, hasDigit, hasSpecialChar } =
        validatePassword(password);
    return isLongEnough && hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
}
