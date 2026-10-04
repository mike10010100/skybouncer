#!/usr/bin/env bash
# ==============================================================================
# Script: check_version_bump.sh
# Purpose: Verifies that Cargo.toml package version was bumped per SemVer and
#          that CHANGELOG.md has an entry for the new version on Pull Requests.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== 📦 Checking Semantic Version Bump & CHANGELOG ===${NC}"

# Determine base git reference
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "")
BASE_REF=""
if [[ -n "${1:-}" ]]; then
    BASE_REF="$1"
elif [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    BASE_REF="origin/${GITHUB_BASE_REF}"
elif [[ "${CURRENT_BRANCH}" != "main" ]] && git rev-parse --verify origin/main >/dev/null 2>&1; then
    BASE_REF="origin/main"
elif [[ "${CURRENT_BRANCH}" != "main" ]] && git rev-parse --verify main >/dev/null 2>&1; then
    BASE_REF="main"
fi

if [[ -z "${BASE_REF}" ]]; then
    echo -e "${YELLOW}Notice: On main branch or no base branch to compare against. Validating current CHANGELOG entry only.${NC}"
    # Verify CHANGELOG.md entry
    CURRENT_VERSION=$(grep -m1 '^[[:space:]]*version[[:space:]]*=' Cargo.toml | awk -F'"' '{print $2}')
    if ! grep -q "## \[${CURRENT_VERSION}\]" CHANGELOG.md; then
        echo -e "${RED}❌ CHANGELOG Check Failed!${NC}"
        echo -e "${RED}CHANGELOG.md does not contain an entry for version [${CURRENT_VERSION}].${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ CHANGELOG.md contains entry for [${CURRENT_VERSION}]${NC}"
    exit 0
fi

# Fetch base ref if not present
if ! git rev-parse --verify "${BASE_REF}" >/dev/null 2>&1; then
    echo "Fetching ${BASE_REF}..."
    git fetch origin "${GITHUB_BASE_REF:-main}" --depth=10 || true
fi

# Extract current version from Cargo.toml
if [[ ! -f "Cargo.toml" ]]; then
    echo -e "${RED}Error: Cargo.toml not found in working directory!${NC}"
    exit 1
fi

CURRENT_VERSION=$(grep -m1 '^[[:space:]]*version[[:space:]]*=' Cargo.toml | awk -F'"' '{print $2}')
if [[ -z "${CURRENT_VERSION}" ]]; then
    echo -e "${RED}Error: Failed to parse current package version from Cargo.toml!${NC}"
    exit 1
fi

# Extract base version from base branch
BASE_VERSION=""
if git cat-file -e "${BASE_REF}:Cargo.toml" 2>/dev/null; then
    BASE_VERSION=$(git show "${BASE_REF}:Cargo.toml" | grep -m1 '^[[:space:]]*version[[:space:]]*=' | awk -F'"' '{print $2}')
fi

if [[ -z "${BASE_VERSION}" ]]; then
    echo -e "${YELLOW}Notice: Could not extract base version from ${BASE_REF}:Cargo.toml (new repository/branch).${NC}"
    echo -e "${GREEN}Current package version: ${CURRENT_VERSION}${NC}"
    exit 0
fi

echo -e "Base version (${BASE_REF}): ${YELLOW}${BASE_VERSION}${NC}"
echo -e "Current PR version:         ${GREEN}${CURRENT_VERSION}${NC}"

# Helper function to parse SemVer parts
parse_semver() {
    local version="$1"
    local major minor patch
    IFS='.' read -r major minor patch <<< "${version%%-*}"
    echo "${major:-0} ${minor:-0} ${patch:-0}"
}

read -r B_MAJ B_MIN B_PAT <<< "$(parse_semver "${BASE_VERSION}")"
read -r C_MAJ C_MIN C_PAT <<< "$(parse_semver "${CURRENT_VERSION}")"

# SemVer comparison
IS_GREATER=false
if (( C_MAJ > B_MAJ )); then
    IS_GREATER=true
elif (( C_MAJ == B_MAJ && C_MIN > B_MIN )); then
    IS_GREATER=true
elif (( C_MAJ == B_MAJ && C_MIN == B_MIN && C_PAT > B_PAT )); then
    IS_GREATER=true
fi

if [[ "${IS_GREATER}" != "true" ]]; then
    echo -e "${RED}❌ Version Check Failed!${NC}"
    echo -e "${RED}Package version '${CURRENT_VERSION}' is not greater than base branch version '${BASE_VERSION}'.${NC}"
    echo -e "${YELLOW}Please bump the version in Cargo.toml according to Semantic Versioning (e.g. patch, minor, or major).${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Version bump valid: ${CURRENT_VERSION} > ${BASE_VERSION}${NC}"

# Verify CHANGELOG.md entry
if [[ ! -f "CHANGELOG.md" ]]; then
    echo -e "${RED}❌ Error: CHANGELOG.md is missing!${NC}"
    exit 1
fi

if ! grep -E "^## \[${CURRENT_VERSION}\]" CHANGELOG.md >/dev/null 2>&1; then
    echo -e "${RED}❌ CHANGELOG Check Failed!${NC}"
    echo -e "${RED}No entry found for version [${CURRENT_VERSION}] in CHANGELOG.md.${NC}"
    echo -e "${YELLOW}Please add a '## [${CURRENT_VERSION}] - YYYY-MM-DD' section to CHANGELOG.md detailing your changes.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ CHANGELOG.md contains entry for [${CURRENT_VERSION}]${NC}"
echo -e "${GREEN}=== 🚀 All Version & Changelog Quality Gates Passed! ===${NC}"
exit 0
