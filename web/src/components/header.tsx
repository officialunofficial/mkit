import { Link } from "waku";

export const Header = () => {
  return (
    <header className="flex flex-wrap items-center gap-4 p-6 lg:fixed lg:top-0 lg:left-0 lg:right-0 lg:bg-white/80 lg:backdrop-blur">
      <h2 className="text-lg font-bold tracking-tight">
        <Link to="/">mkit demo</Link>
      </h2>
      <nav className="flex gap-3 text-sm text-gray-700">
        <Link to="/hash" className="underline-offset-2 hover:underline">
          /hash
        </Link>
        <Link to="/sign" className="underline-offset-2 hover:underline">
          /sign
        </Link>
        <Link to="/attest" className="underline-offset-2 hover:underline">
          /attest
        </Link>
      </nav>
    </header>
  );
};
