class Mkit < Formula
  desc "Content-addressed VCS for creative work (with pluggable notary adapters)"
  homepage "https://github.com/officialunofficial/mkit"
  license "MIT OR Apache-2.0"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-aarch64-macos.tar.gz"
      sha256 "PLACEHOLDER_SHA_AARCH64_MACOS"
    end
    on_intel do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-x86_64-macos.tar.gz"
      sha256 "PLACEHOLDER_SHA_X86_64_MACOS"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-aarch64-linux.tar.gz"
      sha256 "PLACEHOLDER_SHA_AARCH64_LINUX"
    end
    on_intel do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-x86_64-linux.tar.gz"
      sha256 "PLACEHOLDER_SHA_X86_64_LINUX"
    end
  end

  def install
    bin.install "mkit"

    # Man pages (optional — emitted by a future `zig build man` target).
    man1.install "share/man/man1/mkit.1" if File.exist?("share/man/man1/mkit.1")

    # Shell completions (optional — emitted by a future completions target).
    bash_completion.install "share/completions/mkit.bash" => "mkit" if File.exist?("share/completions/mkit.bash")
    zsh_completion.install "share/completions/_mkit" if File.exist?("share/completions/_mkit")
    fish_completion.install "share/completions/mkit.fish" if File.exist?("share/completions/mkit.fish")
  end

  test do
    assert_match "mkit #{version}", shell_output("#{bin}/mkit version")
  end
end
