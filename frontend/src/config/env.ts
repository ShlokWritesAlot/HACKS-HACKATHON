/**
 * BhashaRakshak Frontend Configuration
 *
 * This file centralizes access to environment variables.
 * By defining them here, we ensure type safety and avoid typos when using them
 * across the application.
 *
 * Security: ONLY NEXT_PUBLIC_ variables should ever be accessed in the browser.
 */

export const env = {
  // API connection
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000",
  
  // App metadata
  appName: process.env.NEXT_PUBLIC_APP_NAME || "BhashaRakshak",
  appVersion: process.env.NEXT_PUBLIC_APP_VERSION || "0.1.0",
} as const;
