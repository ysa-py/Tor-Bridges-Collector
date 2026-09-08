/**
 * __mocks__/cloudflare-sockets.ts
 *
 * Vitest mock for the `cloudflare:sockets` Workers runtime module.
 *
 * Provides a controllable `connect()` function that returns fake sockets
 * for unit-testing the probe relay without real network access.
 *
 * v2.5: makeFakeSocket gained two additive optional parameters used by the
 * raw-socket domain-fronted TLS probes —
 *   - `httpResponder`: when set, bytes written to the socket's writable
 *     side are decoded, handed to the responder, and its return value is
 *     enqueued on the readable side (simulating an HTTP server). The
 *     readable stream stays open until a response is produced, so tests
 *     can also assert the exact raw request (Host header, path, upgrade
 *     headers) that the probe put on the wire.
 *   - `openedRejectsWith`: when set, the socket's `opened` promise
 *     rejects with an Error carrying this message (simulating a TLS
 *     handshake / certificate failure).
 * The default behavior (delayMs/shouldError/neverResolve) is unchanged,
 * so the existing tcp-class concurrency and reader-lock tests are
 * unaffected.
 */

// Track reader lifecycle for regression testing (detect leaked reader locks)
export let activeReaders = 0;
export let peakReaders = 0;

export function trackReaderCreate() {
  activeReaders++;
  peakReaders = Math.max(peakReaders, activeReaders);
}

export function trackReaderRelease() {
  activeReaders = Math.max(0, activeReaders - 1);
}

export function resetReaderTracking() {
  activeReaders = 0;
  peakReaders = 0;
}

export function makeFakeSocket(
  delayMs: number = 0,
  shouldError: boolean = false,
  neverResolve: boolean = false,
  httpResponder?: (request: string) => string,
  openedRejectsWith?: string,
) {
  let enqueueAfterDelay: ReturnType<typeof setTimeout> | null = null;
  let pushChunk: ((chunk: Uint8Array) => void) | null = null;

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      pushChunk = (chunk) => controller.enqueue(chunk);
      if (neverResolve) {
        // Never close — simulates a hung bridge that never responds.
        // The readable stream stays open forever, so reader.closed never resolves.
        return;
      }
      if (shouldError) {
        controller.error(new Error("Connection refused"));
      } else if (delayMs > 0) {
        enqueueAfterDelay = setTimeout(() => {
          controller.close(); // connection established, then close
        }, delayMs);
      } else if (!httpResponder) {
        // Fast connect: close immediately
        controller.close();
      }
      // With an httpResponder the stream stays open until the responder
      // produces a response (or the socket is closed).
    },
    cancel() {
      if (enqueueAfterDelay) clearTimeout(enqueueAfterDelay);
    },
  });

  // Override getReader to track lifecycle
  const originalGetReader = readable.getReader.bind(readable);
  (readable as any).getReader = function (options?: any) {
    const reader = originalGetReader(options);
    trackReaderCreate();

    const origReleaseLock = reader.releaseLock.bind(reader);
    reader.releaseLock = function () {
      trackReaderRelease();
      return origReleaseLock();
    };

    const origCancel = reader.cancel.bind(reader);
    reader.cancel = function (reason?: any) {
      trackReaderRelease();
      return origCancel(reason);
    };

    return reader;
  };

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      if (httpResponder && pushChunk) {
        const request = new TextDecoder().decode(chunk);
        const response = httpResponder(request);
        if (response) {
          pushChunk(new TextEncoder().encode(response));
        }
      }
      /* else: discard written data (raw TCP probes never read responses) */
    },
  });

  let closed = false;
  return {
    readable,
    writable,
    // v2.5: the documented handshake signal awaited by safeTlsConnect.
    opened:
      openedRejectsWith !== undefined
        ? Promise.reject(new Error(openedRejectsWith))
        : Promise.resolve({ remoteAddress: "127.0.0.1:443", localAddress: "127.0.0.1:0" }),
    close() {
      closed = true;
      if (enqueueAfterDelay) clearTimeout(enqueueAfterDelay);
    },
    get closed() { return closed; },
  };
}

// Default connect: returns a fake socket synchronously (the real
// cloudflare:sockets connect() also returns synchronously).
// Tests can override with mockConnect.mockImplementation().
export const connect = vi.fn((..._args: any[]) => {
  return makeFakeSocket(0);
}) as any;

// Vitest mock hoisting
import { vi } from "vitest";
