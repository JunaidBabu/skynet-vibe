/**
 * Deno HTTP server to authenticate a Telegram user via Firebase Custom Auth.
 *
 * Listens for POST requests on /authenticate
 * Request Body: { "initData": "..." } (string containing Telegram initData)
 * Success Response (200 OK): { "customToken": "..." }
 * Error Response (400, 401, 500): { "error": "Error message" }
 */

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
// Removed incorrect import: import { HmacSha256 } from "https://deno.land/std@0.224.0/crypto/hmac.ts";
import * as djwt from "https://deno.land/x/djwt@v3.0.2/mod.ts"; // For JWT generation

// --- Configuration ---
const TELEGRAM_BOT_TOKEN = Deno.env.get("TELEGRAM_BOT_TOKEN");
const FIREBASE_SERVICE_ACCOUNT_EMAIL = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_EMAIL");
// Handle potential newline issues in private key from env var
const FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY_RAW = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY");
const FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY = FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY_RAW?.replace(/\\n/g, '\n');
const FIREBASE_PROJECT_ID = Deno.env.get("FIREBASE_PROJECT_ID");
const PORT = parseInt(Deno.env.get("PORT") || "8000", 10);

const FIREBASE_REST_API_URL = `https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit`;

// --- Helper: Validate Environment Variables ---
function checkEnvVariables() {
    if (!TELEGRAM_BOT_TOKEN) throw new Error("Missing environment variable: TELEGRAM_BOT_TOKEN");
    if (!FIREBASE_SERVICE_ACCOUNT_EMAIL) throw new Error("Missing environment variable: FIREBASE_SERVICE_ACCOUNT_EMAIL");
    if (!FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY) throw new Error("Missing environment variable: FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY");
    if (!FIREBASE_PROJECT_ID) throw new Error("Missing environment variable: FIREBASE_PROJECT_ID");
    console.log("Environment variables loaded.");
}

// --- Helper: ArrayBuffer to Hex String ---
function bufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// --- Helper Function: Validate Telegram initData ---
// Uses the globally available Web Crypto API (crypto.subtle)
async function isTelegramDataValid(initDataString: string, botToken: string): Promise<{ isValid: boolean; data?: URLSearchParams; error?: string }> {
    if (!initDataString || !botToken) {
        console.warn("Validation check skipped: Missing initData or botToken.");
        return { isValid: false, error: "Missing initData or botToken for validation." };
    }

    try {
        const urlParams = new URLSearchParams(initDataString);
        const hash = urlParams.get("hash");
        if (!hash) {
            console.warn("Validation failed: No hash found in initData.");
            return { isValid: false, error: "Hash parameter missing in initData." };
        }

        // Prepare data-check-string
        const dataCheckArr: string[] = [];
        const sortedKeys = Array.from(urlParams.keys()).sort();

        for (const key of sortedKeys) {
            if (key !== "hash") {
                dataCheckArr.push(`${key}=${urlParams.get(key)}`);
            }
        }
        const dataCheckString = dataCheckArr.join("\n");

        // 1. Create the secret key using Web Crypto API
        const secretKeyEncoder = new TextEncoder();
        const secretKeyMaterial = await crypto.subtle.importKey(
            "raw",
            secretKeyEncoder.encode("WebAppData"), // Constant string "WebAppData"
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
        const secretKey = await crypto.subtle.sign(
             "HMAC",
             secretKeyMaterial,
             secretKeyEncoder.encode(botToken)
        );

       // 2. Compute the hash using the secret key and Web Crypto API
       const dataEncoder = new TextEncoder();
       const key = await crypto.subtle.importKey(
           "raw",
           secretKey, // Use the derived secret key
           { name: "HMAC", hash: "SHA-256" },
           false,
           ["sign"]
       );
       const computedHashBuffer = await crypto.subtle.sign(
           "HMAC",
           key,
           dataEncoder.encode(dataCheckString)
       );

        const computedHash = bufferToHex(computedHashBuffer);

        // Compare computed hash with the received hash
        if (computedHash === hash) {
            console.log("Telegram initData validation successful.");
            return { isValid: true, data: urlParams };
        } else {
            console.warn("Validation failed: Computed hash does not match received hash.");
            console.debug("Received hash:", hash);
            console.debug("Computed hash:", computedHash);
            console.debug("Data check string:", dataCheckString);
            return { isValid: false, error: "Invalid hash, data integrity check failed." };
        }
    } catch (error) {
        console.error("Error during Telegram data validation:", error);
        return { isValid: false, error: `Validation exception: ${error.message}` };
    }
}

// --- Helper: Create Firebase Custom Token via REST API ---
async function createFirebaseCustomToken(uid: string): Promise<{ token?: string; error?: string }> {
    const serviceAccountEmail = FIREBASE_SERVICE_ACCOUNT_EMAIL!;
    const privateKeyPem = FIREBASE_SERVICE_ACCOUNT_PRIVATE_KEY!;
    const projectId = FIREBASE_PROJECT_ID!;

    const now = Math.floor(Date.now() / 1000);
    const expiry = now + 3600; // Token valid for 1 hour

    const claims = {
        uid: uid,
        // Add additional claims if needed, matching what you might put in admin.auth().createCustomToken()
        // premium: true // Example claim
    };

    try {
        // Import the private key using Web Crypto API
         const privateKey = await crypto.subtle.importKey(
             "pkcs8",
             // Convert PEM string to ArrayBuffer (basic parsing)
             (pem => {
                const base64 = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '');
                const binaryString = atob(base64);
                const len = binaryString.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes.buffer;
             })(privateKeyPem),
             { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
             true, // Key is extractable (required by djwt)
             ["sign"]
         );

        // Create the JWT assertion token using djwt
        const assertionToken = await djwt.create(
            { // Header
                alg: "RS256",
                typ: "JWT",
                kid: undefined, // kid is often not needed for service accounts
            },
            { // Payload
                iss: serviceAccountEmail,
                sub: serviceAccountEmail,
                aud: `${FIREBASE_REST_API_URL}`, // Audience for Identity Toolkit API
                iat: now,
                exp: expiry,
                uid: uid,
                // claims: claims, // Custom claims for the user token
            },
            privateKey // The imported private key
        );
        return { token: assertionToken };

        // Exchange the assertion token for a Firebase custom token via REST API
        const response = await fetch(`${FIREBASE_REST_API_URL}:createCustomToken`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                token: assertionToken,
                returnSecureToken: true, // Must be true
                targetProjectId: projectId, // Specify the target project ID
            }),
        });
        console.log(response);
        if (!response.ok) {
            throw new Error(`Failed to create custom token: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();

        if (!response.ok) {
            console.error("Firebase REST API error response:", data);
            throw new Error(data.error?.message || `Firebase API request failed with status ${response.status}`);
        }

        if (!data.idToken) {
             throw new Error("idToken (custom token) not found in Firebase API response.");
        }

        console.log(`Generated Firebase custom token for UID: ${uid}`);
        return { token: data.idToken };

    } catch (error) {
        console.error("Error creating Firebase custom token via REST API:", error);
        return { error: `Failed to create custom token: ${error.message}` };
    }
}


// --- Main Request Handler ---
async function handler(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const headers = new Headers({
        "Access-Control-Allow-Origin": "*", // Be more specific in production!
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    });

    // Handle CORS preflight requests
    if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers });
    }

    // Only allow POST requests to the /authenticate endpoint
    if (req.method !== "POST" || url.pathname !== "/authenticate") {
        return new Response(JSON.stringify({ error: "Not Found or Method Not Allowed" }), {
            status: 404,
            headers: { ...headers, "Content-Type": "application/json" },
        });
    }

    // --- Get initData from Request Body ---
    let initDataString: string;
    try {
        const body = await req.json();
        initDataString = body.initData;
        if (!initDataString || typeof initDataString !== 'string') {
            throw new Error("'initData' missing or not a string in request body.");
        }
    } catch (error) {
        console.warn("Failed to parse request body:", error);
        return new Response(JSON.stringify({ error: `Bad Request: ${error.message}` }), {
            status: 400,
            headers: { ...headers, "Content-Type": "application/json" },
        });
    }

    // --- Validate initData ---
    const validationResult = await isTelegramDataValid(initDataString, TELEGRAM_BOT_TOKEN!); // Assert non-null as checked earlier
    if (!validationResult.isValid || !validationResult.data) {
        console.warn("Telegram initData validation failed.", validationResult.error);
        return new Response(JSON.stringify({ error: `Unauthorized: ${validationResult.error || 'Invalid Telegram data.'}` }), {
            status: 401,
            headers: { ...headers, "Content-Type": "application/json" },
        });
    }

    // --- Extract User ID ---
    let telegramUserId: string;
    try {
        const userJson = validationResult.data.get("user");
        if (!userJson) throw new Error("User data missing in initData");
        const userData = JSON.parse(userJson);
        if (!userData.id) throw new Error("User ID not found in parsed user data.");

        telegramUserId = String(userData.id); // Ensure it's a string for Firebase UID
        console.log(`Validated Telegram User ID: ${telegramUserId}`);

    } catch (error) {
        console.error("Failed to parse user data from initData:", error);
        return new Response(JSON.stringify({ error: `Bad Request: Could not parse user data from initData. ${error.message}` }), {
            status: 400,
            headers: { ...headers, "Content-Type": "application/json" },
        });
    }

    // --- Generate Firebase Custom Token ---
    const tokenResult = await createFirebaseCustomToken(telegramUserId);
    if (tokenResult.error || !tokenResult.token) {
        return new Response(JSON.stringify({ error: `Internal Server Error: ${tokenResult.error || 'Could not generate token.'}` }), {
            status: 500,
            headers: { ...headers, "Content-Type": "application/json" },
        });
    }

    // --- Success Response ---
    return new Response(JSON.stringify({ customToken: tokenResult.token }), {
        status: 200,
        headers: { ...headers, 
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json" },
    });
}

// --- Start Server ---
try {
    checkEnvVariables(); // Validate environment variables before starting
    console.log(`HTTP server running. Access it at: http://localhost:${PORT}/authenticate`);
    serve(handler, { port: PORT });
} catch (error) {
    console.error("Failed to start server:", error.message);
}
