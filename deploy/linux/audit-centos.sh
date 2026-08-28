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
KERNEL_RELEASE="$(uname -r 2>/dev/null || echo unknown)"

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
printf 'Ожидаемое ядро: 2.6.18-194.26.1.el5xen\nФактическое ядро: %s\n' "$KERNEL_RELEASE"
if [ "$KERNEL_RELEASE" != "2.6.18-194.26.1.el5xen" ]; then
    printf 'ПРЕДУПРЕЖДЕНИЕ: версия ядра отличается от указанной оператором.\n'
fi
capture 00-os-release.txt bash -c 'cat /etc/centos-release /etc/redhat-release 2>/dev/null; uname -a; printf "\\ncmdline: "; cat /proc/cmdline; printf "\\narch: "; uname -m; printf "\\nvirtualization: "; cat /proc/sys/kernel/hostname 2>/dev/null'
if have hostnamectl; then
    capture 01-hostname.txt hostnamectl
else
    capture 01-hostname.txt bash -c 'hostname; cat /etc/sysconfig/network 2>/dev/null'
fi
capture 02-uptime.txt uptime
if have timedatectl; then
    capture 03-timezone.txt timedatectl
else
    capture 03-timezone.txt bash -c 'date; ls -l /etc/localtime; cat /etc/sysconfig/clock 2>/dev/null'
fi

say "Сеть и firewall"
if have ip; then
    capture 10-addresses.txt ip addr show
    capture 11-routes.txt ip route show table all
    capture 12-rules.txt ip rule show
    capture 14-neighbors.txt ip neigh show
else
    capture 10-addresses.txt ifconfig -a
    capture 11-routes.txt route -n
fi
if have ss; then
    capture 13-listening.txt ss -lntup
elif have netstat; then
    capture 13-listening.txt netstat -lntup
else
    capture 13-listening.txt bash -c 'cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6'
fi
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

say "Активные сервисы SysV и systemd"
if have systemctl; then
    capture 20-running-services.txt systemctl list-units --type=service --state=running --no-pager --plain
    capture 21-failed-services.txt systemctl list-units --state=failed --no-pager --plain
    capture 22-enabled-services.txt systemctl list-unit-files --type=service --state=enabled --no-pager --plain
    capture 23-timers.txt systemctl list-timers --all --no-pager --plain
    capture 24-sockets.txt systemctl list-sockets --all --no-pager --plain
else
    printf '# CentOS 5 / legacy SysV init\n' >"$OUT_DIR/20-running-services.txt"
    printf '# systemd отсутствует\n' >"$OUT_DIR/21-failed-services.txt"
fi
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
if ps -eo pid >/dev/null 2>&1; then
    capture 30-processes.txt ps -eo user,pid,ppid,stat,lstart,etime,comm,args
else
    capture 30-processes.txt ps auxww
fi
capture 31-cron.txt bash -c 'for f in /etc/crontab /etc/anacrontab; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done; for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && { echo "--- $d"; ls -la "$d"; }; done'
capture 34-xinetd.txt bash -c 'if [ -d /etc/xinetd.d ]; then ls -la /etc/xinetd.d; for f in /etc/xinetd.d/*; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done; fi'
if have findmnt; then
    capture 32-mounts.txt findmnt -a
else
    capture 32-mounts.txt mount
fi
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

say "Xen и параметры загрузки"
capture 48-xen.txt bash -c 'if [ -d /proc/xen ]; then echo "--- /proc/xen ---"; find /proc/xen -maxdepth 2 -type f -print -exec cat {} \\; 2>/dev/null; fi; if command -v xm >/dev/null 2>&1; then echo "--- xm info ---"; xm info; echo "--- xm list ---"; xm list; fi; if command -v xl >/dev/null 2>&1; then echo "--- xl info ---"; xl info; echo "--- xl list ---"; xl list; fi'
capture 49-sysconfig.txt bash -c 'for f in /etc/sysconfig/network /etc/sysconfig/network-scripts/ifcfg-* /etc/sysconfig/modules/*.modules /etc/sysconfig/iptables /etc/sysconfig/selinux /etc/sysconfig/xendomains /etc/sysconfig/xen; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done'

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
