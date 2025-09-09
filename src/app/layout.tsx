import "./globals.css";
import type { Metadata } from "next";
import Providers from "./providers";

export const metadata: Metadata = {
  title: "CVE Threat Dashboard",
  description: "Browse and analyze CVE vulnerabilities",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-gray-100 text-gray-900 min-h-screen">
        <Providers>
          <header className="bg-white shadow">
            <div className="max-w-6xl mx-auto px-4 py-4 flex justify-between items-center">
              <h1 className="text-xl font-bold">Threat Dashboard</h1>
              <nav className="space-x-4">
                <a href="/" className="hover:underline">Home</a>
                <a href="/cves" className="hover:underline">CVEs</a>
              </nav>
            </div>
          </header>
          <main className="max-w-6xl mx-auto px-4 py-6">{children}</main>
        </Providers>
      </body>
    </html>
  );
}
