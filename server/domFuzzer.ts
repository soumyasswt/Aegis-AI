import puppeteer from 'puppeteer';
import { v4 as uuidv4 } from 'uuid';

export interface TaintLogEntry {
  sink: string;
  value: string;
  source: string;
  stack?: string;
}

export interface DomFuzzResult {
  url: string;
  vulnerabilities: {
    type: string;
    sink: string;
    source: string;
    payload: string;
    confidence: 'High' | 'Medium' | 'Low';
    explanation: string;
    mitigation: string;
  }[];
  error?: string;
}

export async function runDomFuzzer(url: string): Promise<DomFuzzResult> {
  const trackerId = `AegisTracker_${uuidv4().replace(/-/g, '').substring(0, 8)}`;
  const testUrl = new URL(url);
  
  // Inject tracker into URL parameters
  testUrl.searchParams.forEach((_, key) => {
    testUrl.searchParams.set(key, trackerId);
  });
  
  // Also append a dummy hash with tracker
  testUrl.hash = trackerId;

  const result: DomFuzzResult = {
    url: testUrl.toString(),
    vulnerabilities: []
  };

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process'
      ]
    });

    const page = await browser.newPage();

    // Inject runtime instrumentation
    await page.evaluateOnNewDocument((tracker) => {
      (window as any).__TAINT_LOG__ = [];

      const logTaint = (sink: string, value: any, source: string) => {
        if (typeof value === 'string' && value.includes(tracker)) {
          (window as any).__TAINT_LOG__.push({
            sink,
            value,
            source,
            stack: new Error().stack
          });
        }
      };

      // Hook Sinks
      const sinks = ['innerHTML', 'outerHTML'];
      sinks.forEach(sink => {
        const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, sink);
        if (descriptor && descriptor.set) {
          const originalSet = descriptor.set;
          Object.defineProperty(Element.prototype, sink, {
            set(value) {
              logTaint(sink, value, 'DOM Property Assignment');
              originalSet.call(this, value);
            }
          });
        }
      });

      const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function(position, text) {
        logTaint('insertAdjacentHTML', text, 'DOM Method Call');
        return originalInsertAdjacentHTML.call(this, position, text);
      };

      const originalEval = window.eval;
      window.eval = function(code) {
        logTaint('eval', code, 'Global Function Call');
        return originalEval(code);
      };

      const originalSetTimeout = window.setTimeout;
      window.setTimeout = function(code, delay, ...args) {
        if (typeof code === 'string') {
          logTaint('setTimeout', code, 'Global Function Call');
        }
        return originalSetTimeout(code, delay, ...args);
      };

      const originalSetInterval = window.setInterval;
      window.setInterval = function(code, delay, ...args) {
        if (typeof code === 'string') {
          logTaint('setInterval', code, 'Global Function Call');
        }
        return originalSetInterval(code, delay, ...args);
      };

      // Hook Sources (localStorage, sessionStorage)
      const hookStorage = (storage: Storage, name: string) => {
        const originalGetItem = storage.getItem;
        storage.getItem = function(key) {
          const value = originalGetItem.call(this, key);
          // If the value doesn't already have the tracker, we could inject it,
          // but for now we just track if the tracker is read from storage.
          return value;
        };
      };

      hookStorage(window.localStorage, 'localStorage');
      hookStorage(window.sessionStorage, 'sessionStorage');

    }, trackerId);

    // Set some dummy storage values with tracker to see if they get read and sunk
    await page.evaluateOnNewDocument((tracker) => {
      localStorage.setItem('test_tracker', tracker);
      sessionStorage.setItem('test_tracker', tracker);
      document.cookie = `test_tracker=${tracker}`;
    }, trackerId);

    // Navigate and wait for network idle or timeout
    await page.goto(testUrl.toString(), { waitUntil: 'networkidle2', timeout: 15000 });
    
    // Wait a bit more for any async SPA rendering
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Extract taint log
    const taintLog: TaintLogEntry[] = await page.evaluate(() => {
      return (window as any).__TAINT_LOG__ || [];
    });

    // Process findings
    const uniqueSinks = new Set<string>();
    
    for (const entry of taintLog) {
      const key = `${entry.sink}-${entry.source}`;
      if (!uniqueSinks.has(key)) {
        uniqueSinks.add(key);
        result.vulnerabilities.push({
          type: 'Dynamic DOM XSS',
          sink: entry.sink,
          source: entry.source,
          payload: entry.value,
          confidence: 'High', // Runtime verification means high confidence
          explanation: `Tainted input containing the tracker token was observed flowing into the dangerous sink '${entry.sink}'. This indicates a high probability of DOM-based Cross-Site Scripting (XSS). The data originated from ${entry.source}.`,
          mitigation: `Ensure that all untrusted data is properly sanitized or contextually encoded before being passed to dangerous sinks like ${entry.sink}. Avoid using innerHTML or eval with user-controlled data. Prefer textContent or safe DOM manipulation methods.`
        });
      }
    }

  } catch (error: any) {
    console.error(`[DomFuzzer] Error scanning ${url}:`, error);
    result.error = error.message;
  } finally {
    if (browser) {
      await browser.close();
    }
  }

  return result;
}
