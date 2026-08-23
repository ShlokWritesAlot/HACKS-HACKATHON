/** @type {import('next').NextConfig} */
const nextConfig = {
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
  experimental: {},
};

export default nextConfig;
