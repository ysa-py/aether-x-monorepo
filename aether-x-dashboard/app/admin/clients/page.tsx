import { ClientDraft } from "@/components/admin/ClientDraft";

// /admin/clients — AI-assisted client-registry workflow (Part 2 §6).
// Admin drafts a client from a docs URL; only confirmed drafts are served.
export default function AdminClientsPage() {
  return <ClientDraft />;
}
