export interface WafDetectionResult {
  detected: boolean;
  wafName?: string;
  confidence: 'High' | 'Medium' | 'Low';
}

export async function detectWaf(url: string): Promise<WafDetectionResult> {
  try {
    // 1. Check headers from a normal request
    const normalRes = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
    const headers = normalRes.headers;
    
    const serverHeader = headers.get('server')?.toLowerCase() || '';
    if (serverHeader.includes('cloudflare')) return { detected: true, wafName: 'Cloudflare', confidence: 'High' };
    if (serverHeader.includes('akamai')) return { detected: true, wafName: 'Akamai', confidence: 'High' };
    if (serverHeader.includes('imperva') || serverHeader.includes('incapsula')) return { detected: true, wafName: 'Imperva', confidence: 'High' };
    if (serverHeader.includes('awselb') || headers.get('x-amz-cf-id')) return { detected: true, wafName: 'AWS WAF', confidence: 'High' };
    if (headers.get('x-sucuri-id') || headers.get('x-sucuri-cache')) return { detected: true, wafName: 'Sucuri', confidence: 'High' };

    // 2. Send a malicious payload to trigger WAF blocking
    const maliciousUrl = new URL(url);
    maliciousUrl.searchParams.set('aegis_waf_test', '<script>alert(1)</script> UNION SELECT 1,2,3--');
    
    const malRes = await fetch(maliciousUrl.toString(), { signal: AbortSignal.timeout(5000) });
    
    // Check status codes commonly used by WAFs
    if (malRes.status === 403 || malRes.status === 406 || malRes.status === 429 || malRes.status === 503) {
      const malHeaders = malRes.headers;
      const malServer = malHeaders.get('server')?.toLowerCase() || '';
      
      if (malServer.includes('cloudflare')) return { detected: true, wafName: 'Cloudflare', confidence: 'High' };
      if (malServer.includes('akamai')) return { detected: true, wafName: 'Akamai', confidence: 'High' };
      
      const text = await malRes.text();
      if (text.includes('Cloudflare')) return { detected: true, wafName: 'Cloudflare', confidence: 'High' };
      if (text.includes('Access Denied') && text.includes('Reference #')) return { detected: true, wafName: 'Akamai', confidence: 'High' };
      if (text.includes('Incapsula incident ID')) return { detected: true, wafName: 'Imperva', confidence: 'High' };
      if (text.includes('AWS WAF')) return { detected: true, wafName: 'AWS WAF', confidence: 'High' };
      if (text.includes('Sucuri WebSite Firewall')) return { detected: true, wafName: 'Sucuri', confidence: 'High' };
      
      return { detected: true, wafName: 'Generic WAF', confidence: 'Medium' };
    }
    
    return { detected: false, confidence: 'High' };
  } catch (e) {
    return { detected: false, confidence: 'Low' };
  }
}
