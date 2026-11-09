/** @type {import('next').NextConfig} */
const staticExport = process.env.STATIC_EXPORT === "1";

const nextConfig = {
  reactStrictMode: true,
  // "standalone" makes a small self-contained server for the Docker image;
  // "export" makes a static demo build (no backend needed).
  output: staticExport ? "export" : "standalone",
  images: { unoptimized: true },
};

export default nextConfig;
