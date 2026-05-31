class Mkit < Formula
  # Template for the future officialunofficial/homebrew-tap repository.
  # Replace PLACEHOLDER_SHA_* values with hashes from the published release's
  # SHA256SUMS before copying this formula into that tap.
  desc "Content-addressed VCS for creative work (with pluggable notary adapters)"
  homepage "https://github.com/officialunofficial/mkit"
  license "MIT OR Apache-2.0"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA_AARCH64_APPLE_DARWIN"
    end
    on_intel do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA_X86_64_APPLE_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA_AARCH64_UNKNOWN_LINUX_GNU"
    end
    on_intel do
      url "https://github.com/officialunofficial/mkit/releases/download/v#{version}/mkit-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA_X86_64_UNKNOWN_LINUX_GNU"
    end
  end

  def install
    bin.install "mkit"

    # Included in release archives by .github/workflows/release.yml.
    man1.install "share/man/man1/mkit.1" if File.exist?("share/man/man1/mkit.1")

    # Included in release archives by .github/workflows/release.yml.
    bash_completion.install "share/completions/mkit.bash" => "mkit" if File.exist?("share/completions/mkit.bash")
    zsh_completion.install "share/completions/_mkit" if File.exist?("share/completions/_mkit")
    fish_completion.install "share/completions/mkit.fish" if File.exist?("share/completions/mkit.fish")
  end

  test do
    assert_match "mkit #{version}", shell_output("#{bin}/mkit version")
  end
end
