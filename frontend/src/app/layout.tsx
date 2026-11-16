import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI NOC & SOC Operations Platform",
  description: "Unified, multi-tenant AI NOC and SOC operations platform (development build).",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
