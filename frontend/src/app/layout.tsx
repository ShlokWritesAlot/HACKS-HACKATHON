import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { env } from "@/config/env";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: `${env.appName} | AI Scam X-Ray`,
  description: "Detect scam intent in multilingual, obfuscated, and code-mixed SMS messages.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* Security headers that can be applied via meta tags */}
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta name="referrer" content="strict-origin-when-cross-origin" />
      </head>
      <body className={`${inter.className} min-h-screen bg-[#050811] text-slate-100 antialiased selection:bg-cyan-500 selection:text-black`}>
        {children}
      </body>
    </html>
  );
}
