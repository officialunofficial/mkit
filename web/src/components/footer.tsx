export const Footer = () => {
  return (
    // Fixed to bottom-right with muted text, matching the editorial
    // footer style on searchartwith.art (small, unobtrusive, muted).
    <footer className="border-t border-[--color-hairline] px-4 py-6 text-xs text-[--color-muted] sm:px-12">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <span>
          source:{" "}
          <a
            href="https://github.com/officialunofficial/mkit"
            target="_blank"
            rel="noreferrer"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            officialunofficial/mkit
          </a>
        </span>
        <span>
          built with{" "}
          <a
            href="https://waku.gg/"
            target="_blank"
            rel="noreferrer"
            className="underline underline-offset-4 transition-opacity duration-300 hover:opacity-70"
          >
            waku
          </a>
          , deployed on Cloudflare Workers
        </span>
      </div>
    </footer>
  );
};
