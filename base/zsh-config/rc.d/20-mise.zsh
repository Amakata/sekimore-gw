# mise (https://mise.jdx.dev/)
#
# Shims are already on PATH via the image's ENV, so python/node/ruby/php/rust
# resolve from non-interactive shells too. `mise activate` additionally
# installs a zsh hook that switches env on `cd` and loads .mise.toml settings.
if command -v mise >/dev/null 2>&1; then
    eval "$(mise activate zsh)"
fi
