import { cn } from "@/lib/utils";

/** Bordered "terminal window" frame used for the sign-in / sign-up pages. */
export function TerminalWindow({
  path,
  children,
  className,
}: {
  path: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "w-full overflow-hidden rounded-md border bg-card/90 shadow-xl backdrop-blur",
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b px-4 py-2 font-mono text-xs text-muted-foreground">
        <span aria-hidden className="text-signal">
          [■]
        </span>
        <span className="cursor">{path}</span>
      </div>
      <div className="p-6">{children}</div>
    </div>
  );
}
