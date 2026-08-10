- **Add `ja4proxy_sync_clock_monitor_available` (issue #245, F-400-04)**: when
  neither `chronyc` nor `ntpstat` is present, `ja4proxy_sync_clock_drift_seconds`
  is never `Set` — and a never-set gauge is indistinguishable from "drift is
  currently 0" on a dashboard, so clock-skew monitoring could be silently
  disabled in production while the drift panel showed a reassuring flat zero. The
  new gauge reports 1 when drift is genuinely readable and 0 otherwise, and is
  re-set on every check so a monitor that goes unavailable mid-run is visible
  (the existing log warning is once-only by design). Completes the third
  recommendation of F-400-04; the WARN-level log and startup line were already
  in place.
