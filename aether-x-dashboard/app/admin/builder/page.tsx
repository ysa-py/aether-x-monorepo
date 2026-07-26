import { ConfigBuilder } from "@/components/admin/ConfigBuilder";

// /admin/builder — admin config-builder panel. Renders the RGB builder that
// consumes the /v1/transports catalog and builds configs for every Transport
// Network (tcp, kcp, ws, h2, grpc, httpupgrade, xhttp, quic, ...).
export default function AdminBuilderPage() {
  return <ConfigBuilder />;
}
