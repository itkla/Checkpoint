import {
    startRegistration,
    startAuthentication,
    PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/browser';

import { isoBase64URL } from '@simplewebauthn/server/helpers'

const backendApiUrl = process.env.REACT_APP_BACKEND_API_URL || 'https://localhost:3001';

export async function registerPasskey(name: string) {
    try {
        console.log('Starting passkey registration...');

        const optionsResponse = await fetch(backendApiUrl + '/api/auth/passkey/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify({ name }),
        });

        const responseData = await optionsResponse.json();
        console.log('Server response:', responseData);

        if (!optionsResponse.ok) {
            const errorData = await optionsResponse.json();
            console.error('Registration options error:', errorData);
            throw new Error(errorData.error || 'Failed to get registration options');
        }

        const options: PublicKeyCredentialCreationOptionsJSON = responseData;
        console.log('Got registration options:', options);
        console.log('Starting WebAuthn registration with options:', responseData);
        const credential = await startRegistration(responseData);
        console.log('Created credential:', credential);
        const verificationResponse = await fetch(backendApiUrl + '/api/auth/passkey/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`,
            },
            body: JSON.stringify({
                ...credential,
                name, // Include the passkey name
            }),
        });

        const verificationData = await verificationResponse.json();
        console.log('Verification response:', verificationData);

        if (!verificationResponse.ok) {
            const errorData = await verificationResponse.json();
            console.error('Verification error:', errorData);
            throw new Error(errorData.error || 'Failed to verify credential');
        }

        return await verificationData;
    } catch (error) {
        console.error('Passkey registration error:', error);
        throw new Error('Failed to register passkey');
    }
}

export async function loginWithPasskey(email: string) {
    try {
        console.log('Starting passkey authentication...');
        const optionsResponse = await fetch(backendApiUrl + '/api/auth/passkey/login/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });

        const responseData = await optionsResponse.json();
        console.log('Server response:', responseData);

        if (!optionsResponse.ok) {
            throw new Error(responseData.error || 'Failed to start authentication');
        }
        console.log('Starting WebAuthn authentication with options:', responseData);
        const credential = await startAuthentication(responseData);
        console.log('Authentication credential:', credential);
        const verificationResponse = await fetch(backendApiUrl + '/api/auth/passkey/login/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email,
                response: credential,
            }),
        });

        const verificationData = await verificationResponse.json();
        console.log('Verification response:', verificationData);

        if (!verificationResponse.ok) {
            throw new Error(verificationData.error || 'Failed to verify credential');
        }
        localStorage.setItem('token', verificationData.token);
        return verificationData;
    } catch (error: any) {
        console.error('Passkey authentication error:', error);
        throw new Error(error.message || 'Failed to authenticate with passkey');
    }
}
export async function exportCredential(credentialId: string) {
    const credential = await navigator.credentials.get({
        publicKey: {
            allowCredentials: [{
                id: Uint8Array.from(atob(credentialId), c => c.charCodeAt(0)),
                type: 'public-key',
            }],
            challenge: new Uint8Array(32),
            userVerification: 'preferred',
        },
    });

    if (credential && 'exportKey' in credential) {
        return await (credential as any).exportKey();
    }
    throw new Error('Credential export not supported');
}

export async function importCredential(credentialData: any) {
    return await navigator.credentials.create({
        publicKey: {
            ...credentialData,
            challenge: new Uint8Array(32),
        },
    });
}