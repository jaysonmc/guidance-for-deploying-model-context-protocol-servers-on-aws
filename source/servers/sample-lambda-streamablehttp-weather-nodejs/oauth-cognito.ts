/**
 * OAuth handling functionality for MCP server authentication.
 * Provides OAuth 2.0 authorization code flow implementation.
 */

import * as jose from "jose";
import fetch from "node-fetch";

/**
 * Validate a Cognito access token.
 */
async function validateCognitoToken(
  token: string
): Promise<{ isValid: boolean; claims: any }> {
  const region = process.env.AWS_REGION || "us-west-2";
  const user_pool_id = process.env.COGNITO_USER_POOL_ID;
  const client_id = process.env.COGNITO_CLIENT_ID;

  // Get the JWKs from Cognito
  const jwks_url = `https://cognito-idp.${region}.amazonaws.com/${user_pool_id}/.well-known/jwks.json`;

  try {
    // Fetch the JWKS
    const jwks_response = await fetch(jwks_url);
    const jwks = (await jwks_response.json()) as { keys: any[] };

    // Get the key ID from the token header
    const { kid } = await jose.decodeProtectedHeader(token);
    if (!kid) {
      return { isValid: false, claims: {} };
    }

    // Find the correct key
    const key = jwks.keys.find((k: any) => k.kid === kid);
    if (!key) {
      return { isValid: false, claims: {} };
    }

    // Create JWKS
    const JWKS = jose.createLocalJWKSet({ keys: [key] });

    // Define expected issuer
    const issuer = `https://cognito-idp.${region}.amazonaws.com/${user_pool_id}`;

    // Verify the token with RS256 algorithm
    const { payload } = await jose.jwtVerify(token, JWKS, {
      issuer,
      algorithms: ["RS256"],
    });

    // Additional validations for Cognito access tokens
    if (payload.token_use !== "access") {
      console.log(`Invalid token_use: ${payload.token_use}, expected: access`);
      return { isValid: false, claims: {} };
    }

    // For access tokens, client_id is in the 'client_id' claim, not 'aud'
    if (payload.client_id !== client_id) {
      console.log(
        `Invalid client_id: ${payload.client_id}, expected: ${client_id}`
      );
      return { isValid: false, claims: {} };
    }

    return { isValid: true, claims: payload };
  } catch (error) {
    console.error("Token validation error:", error);
    return { isValid: false, claims: {} };
  }
}

/**
 * Validate an access token issued by the MCP server.
 * This function handles both directly issued tokens and tokens bound to Cognito.
 */
export async function validateToken(
  token: string
): Promise<{ isValid: boolean; claims: any }> {
  try {
    console.log(`Validating token: ${token.substring(0, 10)}...`);

    try {
      // First try to decode the token to determine its source
      const { kid } = await jose.decodeProtectedHeader(token);
      console.log(`Token headers:`, { kid });

      // Check if this is a token issued by your MCP server
      if (kid?.startsWith("mcp-")) {
        console.log("Validating as MCP server token");
        const secret_key = process.env.JWT_SECRET_KEY || "your-secret-key";

        // Verify the token with HS256 algorithm
        const { payload: claims } = await jose.jwtVerify(
          token,
          new TextEncoder().encode(secret_key),
          {
            algorithms: ["HS256"],
            audience: "mcp-server",
          }
        );

        console.log(`Token claims keys: ${Object.keys(claims)}`);

        // If this token is bound to a Cognito token, validate it too
        if (claims.cognito_token) {
          if (typeof claims.cognito_token !== "string") {
            console.log("Invalid cognito_token: must be a string");
            return { isValid: false, claims: {} };
          }
          console.log(
            "Token is bound to Cognito token, validating Cognito token"
          );
          const { isValid: isValidCognito } = await validateCognitoToken(
            claims.cognito_token
          );

          if (!isValidCognito) {
            console.log("Cognito token validation failed");
            return { isValid: false, claims: {} };
          }
        }

        console.log("MCP token validation successful");
        return { isValid: true, claims };
      } else {
        console.log("Validating as direct Cognito token");
        return await validateCognitoToken(token);
      }
    } catch (error) {
      console.error("JWT verification failed:", error);
      return { isValid: false, claims: {} };
    }
  } catch (error) {
    console.error(`Token validation error: ${error}`);
    return { isValid: false, claims: {} };
  }
}
