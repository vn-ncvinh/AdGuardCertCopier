#!/system/bin/sh

exec > /data/local/tmp/adguardcert.log
exec 2>&1

set -x

MODDIR=${0%/*}

set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd $1 | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R $selinux_context $2
    else
        chcon -R $default_selinux_context $2
    fi
}

CERTS_DIR=${MODDIR}/system/etc/security/cacerts

if ! [ -d "${CERTS_DIR}" ] || [ -z "$(ls -A ${CERTS_DIR})" ]; then
    exit 0
fi

chown -R 0:0 ${CERTS_DIR}
set_context /system/etc/security/cacerts ${CERTS_DIR}

# Android 14 support
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    rm -f /data/local/tmp/adg-ca-copy
    mkdir -p /data/local/tmp/adg-ca-copy
    mount -t tmpfs tmpfs /data/local/tmp/adg-ca-copy
    cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/adg-ca-copy/

    cp -f ${CERTS_DIR}/* /data/local/tmp/adg-ca-copy/
    chown -R 0:0 /data/local/tmp/adg-ca-copy
    set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/adg-ca-copy

    CERTS_NUM="$(ls -1 /data/local/tmp/adg-ca-copy | wc -l)"
    if [ "$CERTS_NUM" -gt 10 ]; then
        mount --bind /data/local/tmp/adg-ca-copy /apex/com.android.conscrypt/cacerts
        for pid in 1 $(pgrep zygote) $(pgrep zygote64); do
            nsenter --mount=/proc/${pid}/ns/mnt -- \
                /bin/mount --bind /data/local/tmp/adg-ca-copy /apex/com.android.conscrypt/cacerts
        done
    else
        echo "Cancelling replacing CA storage due to safety"
    fi
    umount /data/local/tmp/adg-ca-copy
    rmdir /data/local/tmp/adg-ca-copy
fi
