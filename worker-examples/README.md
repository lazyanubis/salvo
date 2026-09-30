# examples

examples-workers

## Request body regression test

The template's `POST /request_body` route echoes the original bytes using
`payload_with_max_size(16 * 1024)` and returns 413 with `request too large` when
the cumulative body exceeds that limit. The bridge stays streaming; bounded
collection belongs to Salvo's body-reading helpers. Direct stream consumers can
use `Request::limit_body` to enforce a streaming limit.

Start the template in local workerd (using the pinned worker-build in its config):

```bash
cd worker-examples/template
WASM_BINDGEN_USE_JS_SYS=1 wrangler dev --local --port 8787
```

Then, from another terminal:

```bash
cd worker-examples/template
node --test tests/request-body.mjs
```

The tests compare every byte, including binary data and JSON whitespace, across
delayed chunks. They cover the 4096-byte boundary, 8000/16000-byte bodies, the
exact 16384-byte limit, and overflow, with and without `Content-Length`.
Use `WORKER_TEST_URL=http://127.0.0.1:<port>` for a different local port.
