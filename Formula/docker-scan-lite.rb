class DockerScanLite < Formula
  desc "Lightweight Docker image scanner for security analysis"
  homepage "https://github.com/nickciolpan/docker-scan-lite"
  version "1.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.1.0/docker-scan-lite-darwin-arm64.tar.gz"
      sha256 "b2165205b263877607d9cde56ec9517050fafaf899b2f4afef2ba29568f4373c"

      def install
        bin.install "docker-scan-lite-darwin-arm64" => "docker-scan-lite"
      end
    end

    on_intel do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.1.0/docker-scan-lite-darwin-amd64.tar.gz"
      sha256 "42ac9a508cc58d6d478e81a62e08150a0c15851baf7cb91170de83b641548cac"

      def install
        bin.install "docker-scan-lite-darwin-amd64" => "docker-scan-lite"
      end
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.1.0/docker-scan-lite-linux-arm64.tar.gz"
      sha256 "00c1d4398399e2b2f0d50318596628f624e08b74ed403167ce2ba24eb0b2f5d1"

      def install
        bin.install "docker-scan-lite-linux-arm64" => "docker-scan-lite"
      end
    end

    on_intel do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v1.1.0/docker-scan-lite-linux-amd64.tar.gz"
      sha256 "c1b02c453f6ef2a147cfc98a366cff39d6065693f16e0d22787e30175ed8dfb2"

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
