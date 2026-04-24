import { Link } from "waku";

export const Header = () => {
  return (
    // Sticky top-aligned nav borrowed from searchartwith.art: flush top,
    // background matches page, hairline separator, generous left pad on
    // desktop. Flat — no shadow.
    <header className="sticky top-0 z-50 flex items-center justify-between border-b border-[--color-hairline] bg-[--color-bg] px-4 py-4 sm:px-12">
      <Link to="/" className="text-base tracking-tight">
        mkit <span className="text-[--color-muted]">demo</span>
      </Link>
      {/* Hit area preserved via py-2; links stay flat and underline
          only on hover (underline-offset-4 like the source site). */}
      <nav className="flex items-center gap-2 text-sm">
        <Link
          to="/hash"
          className="-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline"
        >
          /hash
        </Link>
        <Link
          to="/sign"
          className="-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline"
        >
          /sign
        </Link>
        <Link
          to="/attest"
          className="-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline"
        >
          /attest
        </Link>
      </nav>
    </header>
  );
};
