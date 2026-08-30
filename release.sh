#!/bin/bash
set -e

# FastAPI JWT Harmony Release Script
# This script helps create releases using GitHub CLI (gh)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if gh is installed and authenticated
check_gh() {
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed. Please install it first:"
        print_error "  brew install gh  # on macOS"
        print_error "  https://cli.github.com/manual/installation"
        exit 1
    fi

    if ! gh auth status &> /dev/null; then
        print_error "GitHub CLI is not authenticated. Please run:"
        print_error "  gh auth login"
        exit 1
    fi

    print_success "GitHub CLI is installed and authenticated"
}

# Validate version format
validate_version() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_error "Expected format: X.Y.Z or X.Y.Z-suffix (e.g., 1.0.0, 1.0.0-alpha)"
        exit 1
    fi
}

# Check if version tag already exists
check_existing_tag() {
    local tag=$1
    if git tag -l | grep -q "^$tag$"; then
        print_error "Tag $tag already exists"
        exit 1
    fi

    if gh release list | grep -q "$tag"; then
        print_error "Release $tag already exists on GitHub"
        exit 1
    fi
}

# Update version in code
update_version() {
    local version=$1
    print_status "Updating version to $version in src/fastapi_jwt_harmony/version.py"
    # Rewrite the assignment, not the file: overwriting it discarded the module docstring
    # on every release.
    python3 - "$version" <<'PYTHON'
import re
import sys
from pathlib import Path

path = Path('src/fastapi_jwt_harmony/version.py')
source = path.read_text()
updated, count = re.subn(r"^__version__ = .*$", f"__version__ = '{sys.argv[1]}'", source, count=1, flags=re.MULTILINE)
if count != 1:
    sys.exit('version.py does not contain a single __version__ assignment')
path.write_text(updated)
PYTHON

    # Stage the version file
    git add src/fastapi_jwt_harmony/version.py
}

# Create and push tag
create_tag() {
    local tag=$1
    local version=$2

    print_status "Creating tag $tag"
    git tag -a "$tag" -m "Release $version"

    print_status "Pushing tag to GitHub"
    git push origin "$tag"
}

# Trigger release workflow
trigger_release() {
    local version=$1

    print_status "Triggering release workflow for version $version"
    gh workflow run release.yml -f version="$version" -f create_tag="false"

    print_success "Release workflow triggered!"
    print_status "You can monitor the progress at:"
    print_status "  https://github.com/$(gh repo view --json owner,name -q '.owner.login + \"/\" + .name')/actions"
}

# Create pre-release
create_prerelease() {
    local suffix=$1

    print_status "Creating pre-release with suffix: $suffix"
    gh workflow run pre-release.yml -f version_suffix="$suffix"

    print_success "Pre-release workflow triggered!"
    print_status "You can monitor the progress at:"
    print_status "  https://github.com/$(gh repo view --json owner,name -q '.owner.login + \"/\" + .name')/actions"
}

# Show help
show_help() {
    echo "FastAPI JWT Harmony Release Script"
    echo ""
    echo "Usage:"
    echo "  $0 release <version>     Create a full release (e.g., 1.0.0)"
    echo "  $0 prerelease <suffix>   Create a pre-release (e.g., alpha, beta, rc1)"
    echo "  $0 check                 Check prerequisites"
    echo "  $0 help                  Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 release 1.0.0         # Create release v1.0.0"
    echo "  $0 release 1.0.1-rc1     # Create release candidate"
    echo "  $0 prerelease alpha       # Create pre-release with 'alpha' suffix"
    echo "  $0 prerelease beta2       # Create pre-release with 'beta2' suffix"
    echo ""
    echo "Prerequisites:"
    echo "  - GitHub CLI (gh) installed and authenticated"
    echo "  - Clean working directory (all changes committed)"
    echo "  - Push access to the repository"
}

# Check working directory is clean
check_clean_working_dir() {
    if [ -n "$(git status --porcelain)" ]; then
        print_warning "Working directory is not clean. Uncommitted changes:"
        git status --short
        echo ""
        print_error "Commit or stash them before releasing: a release must describe a tree that exists in history"
        exit 1
    fi
}

# Main function
main() {
    case "${1:-}" in
        "release")
            if [ -z "${2:-}" ]; then
                print_error "Version is required for release"
                echo ""
                show_help
                exit 1
            fi

            VERSION="$2"
            TAG="v$VERSION"

            print_status "Starting release process for version $VERSION"

            # Checks
            check_gh
            validate_version "$VERSION"
            check_existing_tag "$TAG"
            check_clean_working_dir

            # Confirm release
            echo ""
            print_warning "This will create release $TAG and trigger deployment to PyPI"
            read -p "Are you sure you want to continue? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_status "Release cancelled"
                exit 0
            fi

            # Create release
            update_version "$VERSION"

            # Commit version change if there are changes
            if [ -n "$(git status --porcelain)" ]; then
                git commit -m "chore: bump version to $VERSION" -- src/fastapi_jwt_harmony/version.py
                git push origin HEAD
            fi

            create_tag "$TAG" "$VERSION"

            print_success "Release $TAG created successfully!"
            print_status "GitHub Actions will now:"
            print_status "  1. Build and test the package"
            print_status "  2. Create GitHub release with notes"
            print_status "  3. Publish to PyPI"
            ;;

        "prerelease")
            if [ -z "${2:-}" ]; then
                print_error "Suffix is required for pre-release"
                echo ""
                show_help
                exit 1
            fi

            SUFFIX="$2"

            print_status "Starting pre-release process with suffix: $SUFFIX"

            # Checks
            check_gh
            check_clean_working_dir

            # Confirm pre-release
            echo ""
            print_warning "This will create a pre-release and publish to Test PyPI"
            read -p "Are you sure you want to continue? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_status "Pre-release cancelled"
                exit 0
            fi

            create_prerelease "$SUFFIX"
            ;;

        "check")
            print_status "Checking prerequisites..."
            check_gh

            if git rev-parse --git-dir > /dev/null 2>&1; then
                print_success "Git repository detected"
            else
                print_error "Not in a git repository"
                exit 1
            fi

            if [ -f "pyproject.toml" ]; then
                print_success "pyproject.toml found"
            else
                print_error "pyproject.toml not found"
                exit 1
            fi

            if [ -f "src/fastapi_jwt_harmony/version.py" ]; then
                print_success "Version file found"
                current_version=$(python -c "exec(open('src/fastapi_jwt_harmony/version.py').read()); print(__version__)")
                print_status "Current version: $current_version"
            else
                print_error "Version file not found"
                exit 1
            fi

            print_success "All prerequisites met!"
            ;;

        "help"|"--help"|"-h"|"")
            show_help
            ;;

        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
