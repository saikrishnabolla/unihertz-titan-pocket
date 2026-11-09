#!/system/bin/sh
n=0
while [ "$n" -lt 180 ]; do
 [ "$(getprop sys.boot_completed)" = 1 ] && exit 0
 sleep 2
 n=$((n+1))
done
touch /data/adb/modules/titan_google_play_core/disable
sync
reboot
