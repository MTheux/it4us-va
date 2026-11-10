// TEMPORARY: offline build fallback — uses local Geist fonts instead of Google Fonts.
// Restore registry.ts.bak after build.
import localFont from "next/font/local";
import { GeistPixelSquare } from "geist/font/pixel";

const geist = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-geist" });
const inter = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-inter" });
const notoSans = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-noto-sans" });
const roboto = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-roboto" });
const outfit = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-outfit" });
const dmSans = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-dm-sans" });
const nunitoSans = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-nunito-sans" });
const figtree = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-figtree" });
const raleway = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-raleway" });
const publicSans = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-public-sans" });
const notoSerif = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-noto-serif" });
const robotoSlab = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-roboto-slab" });
const merriweather = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-merriweather" });
const lora = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-lora" });
const playfairDisplay = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2", variable: "--font-playfair-display" });
const geistMono = localFont({ src: "../../../node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.woff2", variable: "--font-geist-mono" });
// Draxen identity fonts (self-hosted, offline-safe).
// Space Grotesk / IBM Plex Mono — "landing" language.
const spaceGrotesk = localFont({ src: "./files/space-grotesk.woff2", variable: "--font-space-grotesk" });
const ibmPlexMono = localFont({ src: "./files/ibm-plex-mono.woff2", variable: "--font-ibm-plex-mono" });
// Barlow / Barlow Condensed / JetBrains Mono — "PTaaS" language (Draxen Core look).
const barlow = localFont({
  src: [
    { path: "./files/barlow-400.woff2", weight: "400", style: "normal" },
    { path: "./files/barlow-500.woff2", weight: "500", style: "normal" },
    { path: "./files/barlow-700.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-barlow",
});
const barlowCondensed = localFont({
  src: [
    { path: "./files/barlow-condensed-700.woff2", weight: "700", style: "normal" },
    { path: "./files/barlow-condensed-900.woff2", weight: "900", style: "normal" },
  ],
  variable: "--font-barlow-condensed",
});
const jetBrainsMono = localFont({
  src: [
    { path: "./files/jetbrains-mono-400.woff2", weight: "400", style: "normal" },
    { path: "./files/jetbrains-mono-700.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-jetbrains-mono",
});

export const fontRegistry = {
  barlow: { label: "Barlow", font: barlow },
  barlowCondensed: { label: "Barlow Condensed", font: barlowCondensed },
  spaceGrotesk: { label: "Space Grotesk", font: spaceGrotesk },
  ibmPlexMono: { label: "IBM Plex Mono", font: ibmPlexMono },
  geist: { label: "Geist", font: geist },
  inter: { label: "Inter", font: inter },
  notoSans: { label: "Noto Sans", font: notoSans },
  nunitoSans: { label: "Nunito Sans", font: nunitoSans },
  figtree: { label: "Figtree", font: figtree },
  roboto: { label: "Roboto", font: roboto },
  raleway: { label: "Raleway", font: raleway },
  dmSans: { label: "DM Sans", font: dmSans },
  publicSans: { label: "Public Sans", font: publicSans },
  outfit: { label: "Outfit", font: outfit },
  geistMono: { label: "Geist Mono", font: geistMono },
  geistPixelSquare: { label: "Geist Pixel Square", font: GeistPixelSquare },
  jetBrainsMono: { label: "JetBrains Mono", font: jetBrainsMono },
  notoSerif: { label: "Noto Serif", font: notoSerif },
  robotoSlab: { label: "Roboto Slab", font: robotoSlab },
  merriweather: { label: "Merriweather", font: merriweather },
  lora: { label: "Lora", font: lora },
  playfairDisplay: { label: "Playfair Display", font: playfairDisplay },
} as const;

export type FontKey = keyof typeof fontRegistry;

export const fontVars = (Object.values(fontRegistry) as Array<(typeof fontRegistry)[FontKey]>)
  .map((f) => f.font.variable)
  .join(" ");

export const fontOptions = (Object.entries(fontRegistry) as [FontKey, { label: string; font: { variable: string } }][]).map(
  ([key, f]) => ({
    key,
    label: f.label,
    variable: f.font.variable,
  }),
);
