#include <tunables/global>

profile ja4proxy-docker flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability net_bind_service,
  deny network raw,

  # Allow access to config and logs
  /app/ r,
  /app/** r,
  /var/log/ja4proxy/ rw,
  /var/log/ja4proxy/** rw,

  # Allow Go runtime specifics
  /proc/sys/kernel/core_pattern r,
  /sys/kernel/mm/transparent_hugepage/enabled r,

  # Deny suspicious paths
  deny /etc/passwd w,
  deny /etc/shadow w,
  deny /bin/** x,
  deny /usr/bin/** x,
}
