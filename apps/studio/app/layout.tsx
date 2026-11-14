import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "AutoSeal Studio",
  description: "Evidence-first evaluator integrity research",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <aside className="sidebar">
            <Link href="/" className="brand" aria-label="AutoSeal Studio home">
              <span className="brand-mark">A<span>.</span></span>
              <span className="brand-words">AUTOSEAL<span>STUDIO</span></span>
            </Link>
            <div className="nav-caption">WORKSPACE</div>
            <nav aria-label="Main navigation">
              <Link className="nav-item" href="/"><span className="nav-glyph">◫</span> Overview</Link>
              <Link className="nav-item" href="/runs"><span className="nav-glyph">◎</span> Runs and evidence</Link>
              <Link className="nav-item" href="/investigation"><span className="nav-glyph">⌁</span> Investigation</Link>
              <Link className="nav-item" href="/repairs"><span className="nav-glyph">✧</span> Repair search</Link>
              <Link className="nav-item" href="/workflows"><span className="nav-glyph">↻</span> Repair workflows</Link>
              <Link className="nav-item" href="/training"><span className="nav-glyph">◈</span> Training evidence</Link>
              <Link className="nav-item" href="/research"><span className="nav-glyph">◇</span> Research status</Link>
            </nav>
            <div className="sidebar-bottom">
              <span className="live-dot" /> Local research mode
              <small>Only checked-in fixtures may be submitted.</small>
            </div>
          </aside>
          <div className="main-shell">
            <header className="topbar">
              <span className="breadcrumb">AutoSeal <span>/</span> Studio</span>
              <span className="topbar-tag">EVIDENCE FIRST</span>
            </header>
            <main>{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
