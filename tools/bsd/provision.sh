#!/bin/sh
# Run as root inside the disposable guest, with the public key as argument 1.
set -eu
trap 'echo TRIPPY_PROVISION_FAILED' EXIT
export PATH=/usr/pkg/bin:/usr/pkg/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
os=$(uname -s)
configure_shell() {
    id trippy >/dev/null
    case "$os" in
    FreeBSD)
        pkg install -y zsh zoxide fzf
        login_shell=/usr/local/bin/zsh
        pw usermod trippy -s "$login_shell"
        ;;
    NetBSD)
        export PKG_PATH="https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/$(uname -m)/$(uname -r | cut -d. -f1).0/All"
        pkg_add zsh zoxide fzf
        login_shell=/usr/pkg/bin/zsh
        usermod -s "$login_shell" trippy
        ;;
    OpenBSD)
        pkg_add zsh zoxide fzf
        login_shell=/usr/local/bin/zsh
        usermod -s "$login_shell" trippy
        ;;
    *) echo "Unsupported guest: $os" >&2; return 1 ;;
    esac
    grep -qxF "$login_shell" /etc/shells || printf '%s\n' "$login_shell" >> /etc/shells
    cat > /home/trippy/.trippy-shell.zsh <<'EOF'
# Managed by scripts/bsd/provision.sh. Personal settings belong in .zshrc.
bindkey -e
bindkey '^[[A' up-line-or-history
bindkey '^[[B' down-line-or-history
bindkey '^[OA' up-line-or-history
bindkey '^[OB' down-line-or-history
bindkey '^I' expand-or-complete
HISTFILE="$HOME/.zsh_history"
HISTSIZE=10000
SAVEHIST=10000
setopt append_history inc_append_history hist_ignore_dups hist_ignore_space
autoload -Uz compinit
compinit
if command -v zoxide >/dev/null 2>&1; then
    eval "$(zoxide init zsh)"
fi
EOF
    # Keep existing personal settings when upgrading a provisioned guest.
    touch /home/trippy/.zprofile /home/trippy/.zshrc
    grep -qxF '[ ! -r "$HOME/.profile" ] || . "$HOME/.profile"' /home/trippy/.zprofile ||
        printf '\n%s\n' '[ ! -r "$HOME/.profile" ] || . "$HOME/.profile"' >> /home/trippy/.zprofile
    grep -qxF '. "$HOME/.trippy-shell.zsh"' /home/trippy/.zshrc ||
        printf '\n%s\n' '. "$HOME/.trippy-shell.zsh"' >> /home/trippy/.zshrc
    chown trippy:$(id -gn trippy) /home/trippy/.trippy-shell.zsh /home/trippy/.zprofile /home/trippy/.zshrc
}
if [ "${1-}" = --shell-only ]; then
    configure_shell
    trap - EXIT
    echo TRIPPY_SHELL_CONFIGURED
    exit 0
fi
key=$1
case "$os" in
FreeBSD)
    env ASSUME_ALWAYS_YES=yes pkg bootstrap
    pkg install -y sudo rsync git ca_root_nss tailscale curl
    id trippy >/dev/null 2>&1 || pw useradd trippy -m -s /bin/sh -G wheel
    mkdir -p /usr/local/etc/sudoers.d
    echo 'trippy ALL=(ALL) NOPASSWD: ALL' > /usr/local/etc/sudoers.d/trippy
    chmod 440 /usr/local/etc/sudoers.d/trippy
    sysrc tailscaled_enable=YES
    service tailscaled start || service tailscaled status
    echo 'console="comconsole"' > /boot/loader.conf.local
    ;;
NetBSD)
    export PKG_PATH="https://cdn.netbsd.org/pub/pkgsrc/packages/NetBSD/$(uname -m)/$(uname -r | cut -d. -f1).0/All"
    pkg_add pkgin sudo rsync git mozilla-rootcerts curl tailscale
    # Recent NetBSD images already initialize the base trust store with certctl.
    if [ -z "$(ls -A /etc/openssl/certs)" ]; then
        mozilla-rootcerts install
    fi
    id trippy >/dev/null 2>&1 || useradd -m -s /bin/sh -G wheel trippy
    mkdir -p /usr/pkg/etc/sudoers.d
    echo 'trippy ALL=(ALL) NOPASSWD: ALL' > /usr/pkg/etc/sudoers.d/trippy
    chmod 440 /usr/pkg/etc/sudoers.d/trippy
    cp /usr/pkg/share/examples/rc.d/tailscaled /etc/rc.d/tailscaled
    grep -q '^tailscaled=YES' /etc/rc.conf || echo 'tailscaled=YES' >> /etc/rc.conf
    /etc/rc.d/tailscaled start || /etc/rc.d/tailscaled status
    printf 'consdev com0\ntimeout=1\nmenu=Boot normally:boot\n' > /boot.cfg
    ;;
OpenBSD)
    pkg_add rust rust-clippy rsync-- git curl tailscale
    id trippy >/dev/null 2>&1 || useradd -m -s /bin/ksh -G wheel trippy
    echo 'permit nopass trippy as root' > /etc/doas.conf
    chmod 600 /etc/doas.conf
    rcctl enable tailscaled
    rcctl start tailscaled
    printf 'set tty com0\nset timeout 1\n' > /etc/boot.conf
    # Rust linking and larger test binaries exceed the default login limits.
    if ! grep -q '^trippy:' /etc/login.conf; then
        printf '\ntrippy:\\\n\t:datasize-cur=infinity:\\\n\t:datasize-max=infinity:\\\n\t:openfiles-cur=4096:\\\n\t:tc=default:\n' >> /etc/login.conf
    fi
    cap_mkdb /etc/login.conf
    usermod -L trippy trippy
    ;;
*) echo "Unsupported guest: $os" >&2; exit 1 ;;
esac
rsync --version >/dev/null
tailscale version >/dev/null
mkdir -p /home/trippy/.ssh /home/trippy/src/trippy /home/trippy/.cache/trippy-target
printf '%s\n' "$key" > /home/trippy/.ssh/authorized_keys
chmod 700 /home/trippy/.ssh
chmod 600 /home/trippy/.ssh/authorized_keys
cat > /home/trippy/.profile <<'EOF'
export PATH="$HOME/.cargo/bin:/usr/pkg/bin:/usr/pkg/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/trippy-target"
export CARGO_BUILD_JOBS=2
# BSD login defaults can constrain rustc well below the available VM memory.
ulimit -d "$(ulimit -H -d)"
ulimit -s "$(ulimit -H -s)"
EOF
chown -R trippy:$(id -gn trippy) /home/trippy
configure_shell
if [ "$os" != OpenBSD ] && [ ! -x /home/trippy/.cargo/bin/rustc ]; then
    curl --fail --location --proto '=https' --tlsv1.2 https://sh.rustup.rs -o /tmp/rustup.sh
    chmod 644 /tmp/rustup.sh
    su -l trippy -c 'sh /tmp/rustup.sh -y --profile minimal --component clippy,rustfmt'
fi
su -l trippy -c 'rustc --version; cargo --version'
touch /var/db/trippy-provisioned
trap - EXIT
echo TRIPPY_PROVISION_COMPLETE
