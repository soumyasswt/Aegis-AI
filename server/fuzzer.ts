import { analyzeDOMXSS } from './astAnalyzer.js';

export async function runFuzzer(endpoints: any[]) {
  const fuzzResults: any[] = [];
  const xssPayload = "<script>alert('AegisXSS')</script>";
  const domXssPayload = "AegisDOMXSS";
  const sqliPayload = "' OR '1'='1";
  
  for (const endpoint of endpoints) {
    const isPost = endpoint.methods.includes('POST');

    // AST-Based DOM XSS Analysis (Run once per endpoint)
    try {
      const res = await fetch(endpoint.url, { signal: AbortSignal.timeout(5000) });
      const html = await res.text();
      const domXssFindings = analyzeDOMXSS(html, endpoint.url);
      fuzzResults.push(...domXssFindings);
    } catch (e) { /* ignore */ }

    // 1. Test Headers for XSS
    try {
      const headerRes = await fetch(endpoint.url, {
        method: 'GET',
        headers: {
          'User-Agent': xssPayload,
          'Referer': xssPayload,
          'X-Forwarded-For': xssPayload
        },
        signal: AbortSignal.timeout(5000)
      });
      const headerText = await headerRes.text();
      if (headerText.includes(xssPayload)) {
        fuzzResults.push({
          url: endpoint.url,
          type: 'Header-Based Reflected XSS',
          severity: 'High',
          confidence: 'High',
          poc: `Headers: User-Agent/Referer/X-Forwarded-For = ${xssPayload}`,
          explanation: 'The payload injected via HTTP headers was reflected unmodified in the response body.',
          mitigation: 'Do not trust HTTP headers. Implement strict context-aware output encoding.'
        });
      }
    } catch (e) { /* ignore */ }

    if (endpoint.params && endpoint.params.length > 0) {
      for (const param of endpoint.params) {
        // 2. Test URL Parameters (GET) for Context-Aware XSS
        try {
          const tracker = `AegisTracker${Math.floor(Math.random() * 10000)}`;
          const xssUrl = new URL(endpoint.url);
          xssUrl.searchParams.set(param, tracker);
          
          // Also test DOM XSS payload
          xssUrl.searchParams.set(param + '_dom', domXssPayload);

          const xssRes = await fetch(xssUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const xssText = await xssRes.text();
          
          if (xssText.includes(tracker)) {
            let context = 'HTML Body';
            const scriptRegex = new RegExp(`<script[^>]*>[\\s\\S]*?${tracker}[\\s\\S]*?<\\/script>`, 'i');
            const urlRegex = new RegExp(`<[^>]+(?:href|src)=["'][^"']*${tracker}[^"']*["'][^>]*>`, 'i');
            const attrRegex = new RegExp(`<[^>]+[a-zA-Z0-9_-]+=["'][^"']*${tracker}[^"']*["'][^>]*>`, 'i');

            if (scriptRegex.test(xssText)) context = 'JavaScript String';
            else if (urlRegex.test(xssText)) context = 'URL Attribute';
            else if (attrRegex.test(xssText)) context = 'HTML Attribute';

            let exploitPayload = '<script>alert("AegisXSS")</script>';
            if (context === 'HTML Attribute') exploitPayload = '"><script>alert("AegisXSS")</script>';
            if (context === 'JavaScript String') exploitPayload = '";alert("AegisXSS");//';
            if (context === 'URL Attribute') exploitPayload = 'javascript:alert("AegisXSS")';

            const verifyUrl = new URL(endpoint.url);
            verifyUrl.searchParams.set(param, exploitPayload);
            const verifyRes = await fetch(verifyUrl.toString(), { signal: AbortSignal.timeout(5000) });
            const verifyText = await verifyRes.text();

            if (verifyText.includes(exploitPayload)) {
              fuzzResults.push({
                url: endpoint.url,
                type: `Reflected XSS (${context})`,
                severity: 'High',
                confidence: 'High',
                poc: verifyUrl.toString(),
                explanation: `The payload in the URL parameter '${param}' was reflected unmodified in a ${context} context, confirming exploitability.`,
                mitigation: 'Implement strict context-aware output encoding and input validation.'
              });
            } else {
              fuzzResults.push({
                url: endpoint.url,
                type: `Reflected Input (${context})`,
                severity: 'Low',
                confidence: 'Medium',
                poc: xssUrl.toString(),
                explanation: `Input is reflected in a ${context} context, but appears to be sanitized or encoded, preventing immediate XSS.`,
                mitigation: 'Ensure context-aware encoding is consistently applied.'
              });
            }
          }
        } catch (e) { /* ignore timeout/network errors */ }

        // 3. Test Form Fields (POST) for Context-Aware XSS
        if (isPost) {
          try {
            const tracker = `AegisTracker${Math.floor(Math.random() * 10000)}`;
            const formData = new URLSearchParams();
            endpoint.params.forEach((p: string) => formData.append(p, p === param ? tracker : 'test'));
            
            const postRes = await fetch(endpoint.url, {
              method: 'POST',
              body: formData,
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              signal: AbortSignal.timeout(5000)
            });
            const postText = await postRes.text();
            
            if (postText.includes(tracker)) {
              let context = 'HTML Body';
              const scriptRegex = new RegExp(`<script[^>]*>[\\s\\S]*?${tracker}[\\s\\S]*?<\\/script>`, 'i');
              const urlRegex = new RegExp(`<[^>]+(?:href|src)=["'][^"']*${tracker}[^"']*["'][^>]*>`, 'i');
              const attrRegex = new RegExp(`<[^>]+[a-zA-Z0-9_-]+=["'][^"']*${tracker}[^"']*["'][^>]*>`, 'i');

              if (scriptRegex.test(postText)) context = 'JavaScript String';
              else if (urlRegex.test(postText)) context = 'URL Attribute';
              else if (attrRegex.test(postText)) context = 'HTML Attribute';

              let exploitPayload = '<script>alert("AegisXSS")</script>';
              if (context === 'HTML Attribute') exploitPayload = '"><script>alert("AegisXSS")</script>';
              if (context === 'JavaScript String') exploitPayload = '";alert("AegisXSS");//';
              if (context === 'URL Attribute') exploitPayload = 'javascript:alert("AegisXSS")';

              const verifyData = new URLSearchParams();
              endpoint.params.forEach((p: string) => verifyData.append(p, p === param ? exploitPayload : 'test'));

              const verifyRes = await fetch(endpoint.url, {
                method: 'POST',
                body: verifyData,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                signal: AbortSignal.timeout(5000)
              });
              const verifyText = await verifyRes.text();

              if (verifyText.includes(exploitPayload)) {
                fuzzResults.push({
                  url: endpoint.url,
                  type: `Reflected XSS POST (${context})`,
                  severity: 'High',
                  confidence: 'High',
                  poc: `POST to ${endpoint.url} with body: ${verifyData.toString()}`,
                  explanation: `The payload in the POST body parameter '${param}' was reflected unmodified in a ${context} context, confirming exploitability.`,
                  mitigation: 'Implement strict context-aware output encoding and input validation for all POST data.'
                });
              } else {
                fuzzResults.push({
                  url: endpoint.url,
                  type: `Reflected Input POST (${context})`,
                  severity: 'Low',
                  confidence: 'Medium',
                  poc: `POST to ${endpoint.url} with body: ${formData.toString()}`,
                  explanation: `Input is reflected in a ${context} context, but appears to be sanitized or encoded, preventing immediate XSS.`,
                  mitigation: 'Ensure context-aware encoding is consistently applied.'
                });
              }
            }
          } catch (e) { /* ignore */ }
        }

        // Test SQLi (Error-Based)
        try {
          const sqliUrl = new URL(endpoint.url);
          sqliUrl.searchParams.set(param, sqliPayload);
          const sqliRes = await fetch(sqliUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const sqliText = await sqliRes.text();
          const sqlErrors = ['syntax error', 'mysql_fetch', 'ORA-', 'PostgreSQL query failed'];
          if (sqlErrors.some(err => sqliText.toLowerCase().includes(err.toLowerCase()))) {
             fuzzResults.push({
              url: endpoint.url,
              type: 'SQL Injection (Error-Based)',
              severity: 'Critical',
              confidence: 'High',
              poc: sqliUrl.toString(),
              explanation: 'The server returned a database error message when injected with SQL syntax, indicating a potential SQL Injection vulnerability.',
              mitigation: 'Use parameterized queries (Prepared Statements) for all database interactions.'
            });
          }
        } catch (e) { /* ignore */ }

        // Test SQLi (Time-Based Blind)
        try {
          const timeSqliUrl = new URL(endpoint.url);
          timeSqliUrl.searchParams.set(param, '1 OR SLEEP(4)=0');
          const start = Date.now();
          await fetch(timeSqliUrl.toString(), { signal: AbortSignal.timeout(8000) });
          const duration = Date.now() - start;
          
          if (duration >= 4000) {
            // Verify it's not just a slow server by sending a normal request
            const normalUrl = new URL(endpoint.url);
            normalUrl.searchParams.set(param, '1');
            const normalStart = Date.now();
            await fetch(normalUrl.toString(), { signal: AbortSignal.timeout(5000) });
            const normalDuration = Date.now() - normalStart;

            if (duration >= normalDuration + 3000) {
               fuzzResults.push({
                url: endpoint.url,
                type: 'Blind SQL Injection (Time-Based)',
                severity: 'Critical',
                confidence: 'High',
                poc: timeSqliUrl.toString(),
                explanation: `The server took significantly longer to respond (${duration}ms) when injected with a time-delay SQL payload compared to a normal request (${normalDuration}ms).`,
                mitigation: 'Use parameterized queries (Prepared Statements) for all database interactions.'
              });
            }
          }
        } catch (e) { /* ignore */ }

        // Test SQLi (Boolean-Based Blind)
        try {
          const trueUrl = new URL(endpoint.url);
          trueUrl.searchParams.set(param, '1 AND 1=1');
          const trueRes = await fetch(trueUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const trueText = await trueRes.text();

          const falseUrl = new URL(endpoint.url);
          falseUrl.searchParams.set(param, '1 AND 1=2');
          const falseRes = await fetch(falseUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const falseText = await falseRes.text();

          const baselineUrl = new URL(endpoint.url);
          baselineUrl.searchParams.set(param, '1');
          const baselineRes = await fetch(baselineUrl.toString(), { signal: AbortSignal.timeout(5000) });
          const baselineText = await baselineRes.text();

          // Differential analysis: True condition matches baseline, False condition differs significantly
          if (Math.abs(trueText.length - baselineText.length) < 50 && Math.abs(falseText.length - trueText.length) > 100) {
             fuzzResults.push({
              url: endpoint.url,
              type: 'Blind SQL Injection (Boolean-Based)',
              severity: 'Critical',
              confidence: 'High',
              poc: `True: ${trueUrl.toString()} | False: ${falseUrl.toString()}`,
              explanation: `The server responded differently to a TRUE boolean condition ('1 AND 1=1') versus a FALSE boolean condition ('1 AND 1=2'), indicating the query logic is vulnerable to Boolean-based Blind SQLi.`,
              mitigation: 'Use parameterized queries (Prepared Statements) for all database interactions.'
            });
          }
        } catch (e) { /* ignore */ }
      }
    }
  }
  return fuzzResults;
}
