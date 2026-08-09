import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = "https://envbank.vercel.app";
  return ["", "/getting-started", "/install"].map((path) => ({ url: `${base}${path}`, lastModified: new Date("2026-08-09"), changeFrequency: "monthly" as const, priority: path ? 0.8 : 1 }));
}
