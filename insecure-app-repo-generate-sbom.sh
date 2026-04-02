#!/bin/bash

# Configuration
REPO_URL="https://github.com/latiotech/insecure-kubernetes-deployments.git"
SUBDIR="insecure-app"
OUTPUT_FILE="insecure-app-repo-sbom-cyclonedx.json"
TEMP_DIR="temp_clone_$(date +%s)"

echo "Creating temporary directory: $TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR" || exit 1

echo "Cloning repository..."
git clone --depth 1 "$REPO_URL" repo_clone

if [ ! -d "repo_clone/$SUBDIR" ]; then
    echo "Error: Directory $SUBDIR not found in repository."
    cd ..
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "Generating SBOM with Syft for: $SUBDIR"
syft "repo_clone/$SUBDIR" -o cyclonedx-json > "../$OUTPUT_FILE"

echo "Cleaning up..."
cd ..
rm -rf "$TEMP_DIR"

echo "SBOM generated successfully: $OUTPUT_FILE"
