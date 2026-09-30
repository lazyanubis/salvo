import assert from 'node:assert/strict';
import { request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const endpoint = new URL('/request_body', process.env.WORKER_TEST_URL ?? 'http://127.0.0.1:8787');
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname), 'Use a local Worker');

function post(body, contentLength, chunkSize = 4096) {
    return new Promise((resolve, reject) => {
        const headers = { 'content-type': 'application/octet-stream' };
        if (contentLength) {
            headers['content-length'] = body.length;
        } else {
            headers['transfer-encoding'] = 'chunked';
        }
        const outgoing = request(endpoint, { method: 'POST', headers }, (response) => {
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('error', reject);
            response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
        });
        outgoing.on('error', reject);
        outgoing.setTimeout(10_000, () => outgoing.destroy(new Error('Worker request timed out')));

        // Send later chunks asynchronously so the adapter cannot mistake the
        // first available network chunk for the complete body.
        async function send() {
            for (let offset = 0; offset < body.length; offset += chunkSize) {
                if (outgoing.destroyed) return;
                outgoing.write(body.subarray(offset, offset + chunkSize));
                await delay(2);
            }
            outgoing.end();
        }
        send().catch(reject);
    });
}

function bytes(size) {
    // Distinct chunks, including NUL and invalid UTF-8, detect truncation,
    // duplication, reordering, and accidental text/JSON conversion.
    return Buffer.from(Array.from({ length: size }, (_, i) => (i * 17 + Math.floor(i / 4096)) % 256));
}

for (const contentLength of [true, false]) {
    const framing = contentLength ? 'Content-Length' : 'chunked without Content-Length';
    for (const size of [0, 1, 4095, 4096, 4097, 8000, 16000, 16384]) {
        test(`${framing}: preserves all ${size} bytes`, async () => {
            const body = bytes(size);
            const response = await post(body, contentLength);
            assert.equal(response.status, 200);
            assert.deepEqual(response.body, body);
        });
    }
    for (const size of [16385, 32768]) {
        test(`${framing}: rejects ${size} bytes`, async () => {
            const response = await post(bytes(size), contentLength);
            assert.equal(response.status, 413);
            assert.equal(response.body.toString(), 'request too large');
        });
    }
}

test('preserves JSON whitespace and UTF-8 across uneven chunks', async () => {
    const body = Buffer.from(`{\n  "sample": "${'中文'.repeat(1000)}", "n": 1.00\n}\n`);
    const response = await post(body, false, 997);
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, body);
});
