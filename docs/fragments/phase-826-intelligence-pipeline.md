### Fixed

- **Analytics: the Intelligence pipeline could not read the event stream at
  all.** `xreadgroup(block=5000)` ran against a Redis client whose
  `socket_timeout` defaulted to 5s in redis-py 8.x — identical deadlines, so
  the client always lost the race and every poll raised `TimeoutError` on a 1s
  retry loop. Not one event had ever been ingested, so no detection ran, no
  findings were written, and the console's Intelligence panel reported "No
  high-confidence findings active" indefinitely. The same defect affected the
  ti_feeds runner and the management console's live event feed. All three
  clients now pin `socket_timeout` explicitly, and the consumer clamps its
  block window below that budget so a hot-reloaded `stream.timeout_ms` cannot
  re-create the collision. (Phase 826, layer 1)
