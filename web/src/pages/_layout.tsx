import "../styles.css";

import type { ReactNode } from "react";
import { Footer } from "../components/footer";
import { Header } from "../components/header";

type RootLayoutProps = { children: ReactNode };

export default async function RootLayout({ children }: RootLayoutProps) {
  const data = await getData();

  return (
    <div>
      <meta name="description" content={data.description} />
      <link rel="icon" type="image/png" href={data.icon} />
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
      {/* Geist (sans) + Geist Mono, matching searchartwith.art. */}
      <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500&display=swap"
        precedence="font"
      />
      <Header />
      {/* Editorial layout: full-width top-aligned, generous horizontal
          padding, no centered card. Matches the searchartwith.art
          container feel — content flows top-down, header sticky. */}
      <main className="px-6 pt-6 pb-24 sm:px-12">{children}</main>
      <Footer />
    </div>
  );
}

const getData = async () => {
  const data = {
    description: "An internet website!",
    icon: "/images/favicon.png",
  };

  return data;
};

export const getConfig = async () => {
  return {
    render: "static",
  } as const;
};
