class DockerScanLite < Formula
  desc "Lightweight Docker image scanner for security analysis"
  homepage "https://github.com/nickciolpan/docker-scan-lite"
  version "1.0.0"
  license "MIT"
  
  on_macos do
    on_arm do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v#{version}/docker-scan-lite-darwin-arm64.tar.gz"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Placeholder - will be updated on first release
    end
    
    on_intel do
      url "https://github.com/nickciolpan/docker-scan-lite/releases/download/v#{version}/docker-scan-lite-darwin-amd64.tar.gz"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Placeholder - will be updated on first release
    end
  end

  def install
    bin.install "docker-scan-lite-darwin-arm64" => "docker-scan-lite" if Hardware::CPU.arm?
    bin.install "docker-scan-lite-darwin-amd64" => "docker-scan-lite" if Hardware::CPU.intel?
  end

  test do
    system "#{bin}/docker-scan-lite", "--help"
    system "#{bin}/docker-scan-lite", "--version"
  end
end 