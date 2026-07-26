import { SubscriberPortal } from "@/components/user/SubscriberPortal";

// /user/dashboard?token=<subtoken> — the canonical subscriber entry point.
// Renders the RGB glassmorphism portal; the token is the credential.
export default function DashboardPage() {
  return <SubscriberPortal />;
}
