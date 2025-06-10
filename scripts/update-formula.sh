#!/bin/bash
set -e

VERSION=${1:-"1.0.0"}
REPO="nickciolpan/docker-scan-lite"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

echo "Generating SHA256 hashes for version $VERSION..."

# Download and calculate SHA256 for ARM64
ARM64_URL="https://github.com/$REPO/releases/download/v$VERSION/docker-scan-lite-darwin-arm64.tar.gz"
AMD64_URL="https://github.com/$REPO/releases/download/v$VERSION/docker-scan-lite-darwin-amd64.tar.gz"

# Check if releases exist
if ! curl -s --head "$ARM64_URL" | head -n 1 | grep -q "200 OK"; then
    echo "❌ Release $VERSION not found. Please create the release first."
    exit 1
fi

# Calculate SHA256 hashes
echo "📥 Downloading ARM64 binary..."
ARM64_SHA=$(curl -sL "$ARM64_URL" | shasum -a 256 | cut -d' ' -f1)

echo "📥 Downloading AMD64 binary..."
AMD64_SHA=$(curl -sL "$AMD64_URL" | shasum -a 256 | cut -d' ' -f1)

echo ""
echo "✅ SHA256 Hashes:"
echo "ARM64: $ARM64_SHA"
echo "AMD64: $AMD64_SHA"

# Update the formula
FORMULA_FILE="Formula/docker-scan-lite.rb"

if [ -f "$FORMULA_FILE" ]; then
    echo ""
    echo "🔧 Updating $FORMULA_FILE..."
    
    # Use sed to replace the placeholder SHA256 values
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed
        sed -i '' "s/sha256 \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"  # Placeholder - will be updated on first release/sha256 \"$ARM64_SHA\"/g" "$FORMULA_FILE"
    else
        # Linux sed
        sed -i "s/sha256 \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"  # Placeholder - will be updated on first release/sha256 \"$ARM64_SHA\"/g" "$FORMULA_FILE"
    fi
    
    # Replace the second occurrence with AMD64
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/sha256 \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"/sha256 \"$AMD64_SHA\"/" "$FORMULA_FILE"
    else
        sed -i "s/sha256 \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"/sha256 \"$AMD64_SHA\"/" "$FORMULA_FILE"
    fi
    
    echo "✅ Formula updated successfully!"
    echo ""
    echo "📝 Next steps:"
    echo "1. Review the updated formula: $FORMULA_FILE"
    echo "2. Test the formula: brew install --build-from-source $FORMULA_FILE"
    echo "3. Commit and push the changes"
else
    echo "❌ Formula file not found: $FORMULA_FILE"
    exit 1
fi 