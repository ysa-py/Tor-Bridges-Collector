/**
 * __mocks__/cloudflare-sockets.ts
 *
 * Vitest mock for the `cloudflare:sockets` Workers runtime module.
 *
 * Provides a controllable `connect()` function that returns fake sockets
 * for unit-testing the probe relay without real network access.
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
) {
  let enqueueAfterDelay: ReturnType<typeof setTimeout> | null = null;

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
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
      } else {
        // Fast connect: close immediately
        controller.close();
      }
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
    write() { /* discard written data */ },
  });

  let closed = false;
  return {
    readable,
    writable,
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
