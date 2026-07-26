import { BentoGrid } from "@/components/BentoGrid";
import { TopBar } from "@/components/TopBar";

export default function HomePage() {
  return (
    <main className="mx-auto max-w-7xl px-4 pb-10">
      <TopBar />
      <BentoGrid />
    </main>
  );
}
