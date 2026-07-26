"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { I18nProvider } from "@/lib/i18n";

/** Root client providers: TanStack Query + i18n (dir/locale). */
export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Exponential backoff fallback for live NOC polling.
            retry: (failureCount) => failureCount < 4,
            retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 15000),
            staleTime: 1500,
            refetchOnWindowFocus: true,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={client}>
      <I18nProvider>{children}</I18nProvider>
    </QueryClientProvider>
  );
}
