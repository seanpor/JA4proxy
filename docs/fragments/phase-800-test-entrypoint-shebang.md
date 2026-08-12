- **Fix the test image's entrypoint shebang (Phase 800)**:
  `scripts/docker-entrypoint.sh` declared `#!/bin/bash`, but it is the ENTRYPOINT
  of `deploy/docker/Dockerfile.test`, whose base is `python:3.14.6-alpine3.24` —
  Alpine ships no bash. Docker reported `exec
  /app/scripts/docker-entrypoint.sh: no such file or directory`, which is
  misleading: the script exists, its shebang's interpreter does not. That failed
  `make perf-test` with exit 255 and aborted `make bench-all` before
  `test-go-perf`, `load-test` and `measure-mttr` could run. The script contains no
  bashisms, so `#!/bin/sh` is correct rather than a workaround and no bash needs
  adding to the image.
