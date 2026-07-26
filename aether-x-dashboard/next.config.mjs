/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server bundle (.next/standalone) so the production
  // container ships only the traced runtime dependencies instead of the whole
  // node_modules tree. Required by deploy/docker/dashboard.Dockerfile.
  output: "standalone",
};

export default nextConfig;
