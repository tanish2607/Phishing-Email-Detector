import type { Metadata } from "next";
import { Outfit, Inter } from "next/font/google";
import "./globals.css";

const outfit = Outfit({
  variable: "--font-outfit",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700", "800", "900"],
});

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700", "800"],
});

export const metadata: Metadata = {
  title: "PhishShield AI - Agentic Phishing Detection Dashboard",
  description: "Dissect email headers, URLs, and text using parallel LangGraph agentic workflows and local machine learning models.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${outfit.variable} ${inter.variable} dark antialiased`}
    >
      <body className="bg-zinc-950 text-zinc-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
