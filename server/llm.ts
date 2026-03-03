import { GoogleGenAI } from '@google/genai';

export async function analyzeEndpoints(endpoints: any[], verifiedVulnerabilities: any[]) {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
      return [{
        url: 'System Configuration',
        type: 'Missing API Key',
        severity: 'Low',
        confidence: 'High',
        explanation: 'The GEMINI_API_KEY environment variable is missing or set to a placeholder. LLM-augmented analysis was skipped.',
        mitigation: 'Please configure a valid Gemini API Key in the AI Studio Secrets panel to enable AI-powered vulnerability analysis.',
      }];
    }

    const ai = new GoogleGenAI({ apiKey });

    const prompt = `
    You are an expert penetration tester. Review the following verified vulnerabilities and discovered endpoints.
    
    Discovered Endpoints: ${JSON.stringify(endpoints.slice(0, 10))}
    Verified Vulnerabilities (from active scanning): ${JSON.stringify(verifiedVulnerabilities)}
    
    Task:
    1. For the verified vulnerabilities, provide deeper context or suggest advanced exploit chains if applicable.
    2. Based on the endpoints, suggest 1-2 highly probable theoretical vulnerabilities that require manual testing (mark confidence as "Low").
    
    Return the response as a JSON array of objects with the following structure:
    [{
      "url": "string",
      "type": "string (e.g., XSS, SQLi, CSRF, Misconfiguration)",
      "severity": "string (Critical, High, Medium, Low)",
      "confidence": "string (High, Medium, Low)",
      "explanation": "string (Detailed reasoning)",
      "mitigation": "string (How to fix it)",
      "poc": "string (Example payload or request)"
    }]
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-3.1-pro-preview',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      }
    });

    const text = response.text;
    if (text) {
      return JSON.parse(text);
    }
    return [];
  } catch (error: any) {
    console.error('LLM Analysis error:', error);
    
    if (error.message?.includes('API key not valid') || error.message?.includes('API_KEY_INVALID')) {
      return [{
        url: 'System Configuration',
        type: 'Invalid API Key',
        severity: 'Low',
        confidence: 'High',
        explanation: 'The provided Gemini API Key is invalid. LLM-augmented analysis could not be completed.',
        mitigation: 'Please check your Gemini API Key in the AI Studio Secrets panel and ensure it is correct.',
      }];
    }
    
    return [];
  }
}
