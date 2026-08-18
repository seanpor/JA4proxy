- **Fingerprint and IP detail pages render their data again (Phase 827)**: both
  templates wrapped their Alpine component in `{% block scripts %}`, but
  `base.html` declares `{% block extra_scripts %}`. Jinja2 discards a block the
  parent does not declare — silently, with no warning and no marker in the
  output — so `fingerprintPage()` and `ipPage()` were never emitted, `x-data`
  threw a ReferenceError, no profile fetch was ever made, and every counter on
  both pages stayed empty. The `/api/v1/fingerprints/{ja4}/profile` and
  `/api/v1/ip/{ip}/profile` endpoints were correct throughout and return real
  data when called directly.
- **Failed profile fetches are now visible (Phase 827)**: a non-OK response left
  every binding on its zero default, making a 403 or a 500 indistinguishable
  from a fingerprint with no traffic. Both pages now show a banner naming the
  cause.
- **`[x-cloak]` CSS rule added (Phase 827)**: nothing in the app defined it, so
  Alpine's `x-cloak` attribute was inert and every element using it — including
  the confirmation modal — flashed visibly on load before Alpine initialised.
- **Guard test `management/tests/test_template_blocks.py` (Phase 827)**: asserts
  every `{% block %}` a child template defines exists somewhere in its parent
  chain, and that every `x-data="fn()"` has a `function fn()` in content the
  parent actually renders. This failure mode is invisible to route tests, unit
  tests and template-render tests alike — the page returns 200 and the HTML is
  well-formed.
