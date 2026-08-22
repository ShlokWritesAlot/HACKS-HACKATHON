import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Strict React mode — catches common bugs early
  reactStrictMode: true,

  // Disable the default X-Powered-By header (information disclosure)
  poweredByHeader: false,

  // Security headers applied to all routes
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-DNS-Prefetch-Control",
            value: "on",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            key: "Permissions-Policy",
            value: "geolocation=(), microphone=(), camera=(), payment=()",
          },
        ],
      },
    ];
  },

  // Experimental features
  experimental: {
    // Enforce that only NEXT_PUBLIC_ env vars are exposed to browser
    // (this is Next.js default behaviour; documented here for clarity)
  },
};

export default nextConfig;
