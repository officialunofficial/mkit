export const Footer = () => {
  return (
    <footer className="p-6 text-sm text-gray-600 lg:fixed lg:right-0 lg:bottom-0">
      <div>
        source:{" "}
        <a
          href="https://github.com/officialunofficial/mkit"
          target="_blank"
          rel="noreferrer"
          className="underline"
        >
          officialunofficial/mkit
        </a>{" "}
        · built with{" "}
        <a href="https://waku.gg/" target="_blank" rel="noreferrer" className="underline">
          waku
        </a>
        , deployed on Cloudflare Workers
      </div>
    </footer>
  );
};
