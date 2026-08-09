import { CopyButton } from "./copy-button";

export function CodeBlock({ children, label = "Terminal command" }: { children: string; label?: string }) {
  return (
    <div className="code-block">
      <div className="code-bar"><span>{label}</span><CopyButton value={children} label={`Copy ${label.toLowerCase()}`} /></div>
      <pre tabIndex={0}><code>{children}</code></pre>
    </div>
  );
}
