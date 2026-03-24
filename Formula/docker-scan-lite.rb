class DockerScanLite < Formula
  desc "Lightweight Docker image scanner for security analysis"
  homepage "https://github.com/nickciolpan/docker-scan-lite"
  version "1.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.0.0/docker-scan-lite-darwin-arm64.tar.gz"
      sha256 "d0c99db730f65caa52c3c3e495f14a83e0fc0880f770968e48d4dcdad8d9ca60"

      def install
        bin.install "docker-scan-lite-darwin-arm64" => "docker-scan-lite"
      end
    end

    on_intel do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.0.0/docker-scan-lite-darwin-amd64.tar.gz"
      sha256 "35c8e34e2a356f728fe3aed2fb2a9a8efd4fdd473786651ac4bfef0fa05f73ca"

      def install
        bin.install "docker-scan-lite-darwin-amd64" => "docker-scan-lite"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.0.0/docker-scan-lite-linux-arm64.tar.gz"
      sha256 "c8cb7c9aa6c484814e4eb2087f620f6800dc7487f84ad2bf5b3356d18f80800d"

      def install
        bin.install "docker-scan-lite-linux-arm64" => "docker-scan-lite"
      end
    end

    on_intel do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.0.0/docker-scan-lite-linux-amd64.tar.gz"
      sha256 "a9866ac26478e5d20965a120f47c5e32593618306bf5f8aa7b863cda7738a4db"

      def install
        bin.install "docker-scan-lite-linux-amd64" => "docker-scan-lite"
      end
    end
  end

  test do
    system "#{bin}/docker-scan-lite", "--help"
    system "#{bin}/docker-scan-lite", "--version"
  end
end
