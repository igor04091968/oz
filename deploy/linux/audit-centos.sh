#!/usr/bin/env bash
# Аудит старого CentOS перед переносом работающих сервисов на Debian.
# Скрипт только читает состояние системы и не устанавливает пакеты, не меняет
# службы, маршруты, sysctl или firewall.

set -u
umask 077

HOSTNAME_VALUE="$(hostname -s 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${1:-./centos-audit-${HOSTNAME_VALUE}-${STAMP}}"
ARCHIVE="${OUT_DIR}.tar.gz"

mkdir -p "$OUT_DIR" || {
    printf 'Не удалось создать каталог: %s\n' "$OUT_DIR" >&2
    exit 1
}

LOG="$OUT_DIR/audit.log"
exec > >(tee "$LOG") 2>&1

say() {
    printf '\n===== %s =====\n' "$1"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

run() {
    # Не останавливаем аудит из-за отсутствующей утилиты или ограниченных прав.
    "$@" 2>&1 || printf '[команда завершилась с ошибкой: %s]\n' "$*"
}

capture() {
    local file="$1"
    shift
    {
        printf '# command: %s\n' "$*"
        "$@"
    } 2>&1 | redact >"$OUT_DIR/$file" || true
}

redact() {
    # Удаляем значения типовых секретов перед сохранением отчета. Это не
    # замена Presidio, а локальный fail-safe для автономного запуска на сервере.
    sed -E \
        -e 's/((password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|authorization|credential)[[:space:]]*[=:][[:space:]]*)[^[:space:];,]+/\1[REDACTED]/Ig' \
        -e 's/(Bearer[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig' \
        -e 's/(Basic[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig' \
        -e 's/(https?:\/\/[^:[:space:]]+):[^@[:space:]]+@/\1:[REDACTED]@/Ig'
}

say "Метаданные ОС и ядра"
capture 00-os-release.txt bash -c 'cat /etc/centos-release /etc/redhat-release 2>/dev/null; uname -a; printf "\\ncmdline: "; cat /proc/cmdline; printf "\\narch: "; uname -m'
capture 01-hostname.txt hostnamectl
capture 02-uptime.txt uptime
capture 03-timezone.txt timedatectl

say "Сеть и firewall"
capture 10-addresses.txt ip -brief address
capture 11-routes.txt ip route show table all
capture 12-rules.txt ip rule show
capture 13-listening.txt ss -lntup
capture 14-neighbors.txt ip neigh show
capture 15-resolver.txt bash -c 'cat /etc/resolv.conf; printf "\\n--- hosts ---\\n"; cat /etc/hosts'
if have firewall-cmd; then
    capture 16-firewalld.txt firewall-cmd --list-all-zones
fi
if have firewall-cmd; then
    capture 17-firewalld-state.txt firewall-cmd --state
fi
if have iptables-save; then
    capture 18-iptables.txt iptables-save
fi
if have nft; then
    capture 19-nftables.txt nft list ruleset
fi

say "Активные сервисы systemd"
capture 20-running-services.txt systemctl list-units --type=service --state=running --no-pager --plain
capture 21-failed-services.txt systemctl list-units --state=failed --no-pager --plain
capture 22-enabled-services.txt systemctl list-unit-files --type=service --state=enabled --no-pager --plain
capture 23-timers.txt systemctl list-timers --all --no-pager --plain
capture 24-sockets.txt systemctl list-sockets --all --no-pager --plain
if have service; then
    capture 25-sysv-services.txt service --status-all
fi
if have chkconfig; then
    capture 26-chkconfig.txt chkconfig --list
fi

# Для каждого реально работающего unit’а сохраняем только свойства, полезные
# для переноса: бинарь, пользователь, каталоги, зависимости и политика restart.
if have systemctl; then
    systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
        | awk '{print $1}' \
        | while IFS= read -r unit; do
            [ -n "$unit" ] || continue
            safe_unit="${unit//[^A-Za-z0-9_.@-]/_}"
            systemctl show "$unit" \
                -p Id -p Description -p LoadState -p ActiveState -p SubState \
                -p FragmentPath -p ExecStart -p User -p Group -p DynamicUser \
                -p WorkingDirectory -p RootDirectory -p Restart -p RestartSec \
                -p After -p Requires -p Wants -p BindsTo -p PartOf \
                --no-pager 2>&1 | redact >"$OUT_DIR/service-${safe_unit}.properties" || true
            systemctl cat "$unit" 2>&1 | redact >"$OUT_DIR/service-${safe_unit}.unit" || true
        done
fi

say "Процессы, cron и журналы запуска"
capture 30-processes.txt ps -eo user,pid,ppid,stat,lstart,etime,comm,args --forest
capture 31-cron.txt bash -c 'for f in /etc/crontab /etc/anacrontab; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done; find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f -print 2>/dev/null'
capture 32-mounts.txt findmnt -a
capture 33-fstab.txt cat /etc/fstab

say "Ядерные настройки"
capture 40-sysctl-effective.txt sysctl -a
capture 41-sysctl-config.txt bash -c 'for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done'
capture 42-modules-loaded.txt lsmod
capture 43-modprobe-config.txt bash -c 'for f in /etc/modprobe.d/* /usr/lib/modprobe.d/*; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done'
capture 44-limits.txt bash -c 'for f in /etc/security/limits.conf /etc/security/limits.d/*; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done'
capture 45-kernel-modules-cmdline.txt bash -c 'cat /proc/modules; printf "\\n--- cmdline ---\\n"; cat /proc/cmdline'
if have grubby; then
    capture 47-grubby.txt grubby --info=ALL
fi
capture 46-security.txt bash -c 'getenforce 2>/dev/null || true; sestatus 2>/dev/null || true; aa-status 2>/dev/null || true'

say "Поддержка контейнеров и виртуализации"
if have docker; then capture 50-docker.txt docker ps --all --no-trunc; fi
if have podman; then capture 51-podman.txt podman ps --all --no-trunc; fi
if have virsh; then capture 52-libvirt.txt virsh list --all; fi

say "Точечные сведения о runtime-пакетах"
# Полный rpm-список намеренно не собирается. Фиксируем только пакет-владельца
# исполняемых файлов активных процессов, когда это возможно.
if have rpm && have readlink; then
    ps -eo comm= 2>/dev/null | sort -u | while IFS= read -r command; do
        path="$(command -v "$command" 2>/dev/null || true)"
        [ -n "$path" ] || continue
        rpm -qf "$path" 2>/dev/null || true
    done | sort -u | redact >"$OUT_DIR/60-runtime-packages.txt"
fi

say "Итог"
printf 'Каталог отчета: %s\n' "$OUT_DIR"
printf 'Файлов собрано: %s\n' "$(find "$OUT_DIR" -type f | wc -l)"

tar -czf "$ARCHIVE" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")" 2>/dev/null || true
chmod 600 "$ARCHIVE" "$LOG" 2>/dev/null || true
printf 'Архив: %s\n' "$ARCHIVE"
