import LoginButton from './SsoButton';

const SocialLogin: React.FC = () => {
    const handleGoogleLogin = () => {
        // Add Google login logic here
    };

    const handleLineLogin = () => {
        // Add LINE login logic here
    };

    return (
        <div id="sso-login">
            <div className="flex items-center my-4 px-8">
                <hr className="flex-grow border-gray-300" />
                <span className="mx-4 text-gray-600">または</span>
                <hr className="flex-grow border-gray-300" />
            </div>
            <div className="flex items-center justify-center space-x-4">
                <LoginButton
                    icon="/assets/google.svg"
                    provider="Google"
                    onClick={handleGoogleLogin}
                />
                <LoginButton
                    icon="/assets/line.png"
                    provider="LINE"
                    onClick={handleLineLogin}
                />
            </div>
        </div>
    );
};

export default SocialLogin;