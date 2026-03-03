import * as cheerio from 'cheerio';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export function analyzeDOMXSS(html: string, targetUrl: string) {
  const findings: any[] = [];
  try {
    const $ = cheerio.load(html);
    const scripts = $('script').map((i, el) => $(el).html()).get().filter(Boolean);

    for (const script of scripts) {
      try {
        const ast = acorn.parse(script, { ecmaVersion: 2020, sourceType: 'script' });
        const taintedVars = new Set<string>();

        const isSource = (node: any): boolean => {
          if (!node) return false;
          if (node.type === 'MemberExpression') {
            const objName = node.object?.name;
            const propName = node.property?.name || node.property?.value;
            if (objName === 'location' && ['search', 'hash', 'pathname', 'href'].includes(propName)) return true;
            if (objName === 'document' && ['URL', 'documentURI', 'baseURI', 'referrer', 'cookie'].includes(propName)) return true;
            if (['localStorage', 'sessionStorage'].includes(objName) && propName === 'getItem') return true;
            if (node.object?.object?.name === 'window' && node.object?.property?.name === 'location') {
              if (['search', 'hash', 'pathname', 'href'].includes(propName)) return true;
            }
          }
          if (node.type === 'CallExpression' && node.callee?.type === 'MemberExpression') {
             if (node.callee.property?.name === 'get') return true; 
          }
          if (node.type === 'Identifier' && taintedVars.has(node.name)) return true;
          if (node.type === 'BinaryExpression') return isSource(node.left) || isSource(node.right);
          if (node.type === 'TemplateLiteral') return node.expressions.some(isSource);
          return false;
        };

        walk.simple(ast, {
          VariableDeclarator(node: any) {
            if (node.id.type === 'Identifier' && isSource(node.init)) {
              taintedVars.add(node.id.name);
            }
          },
          AssignmentExpression(node: any) {
            if (node.left.type === 'Identifier' && isSource(node.right)) {
              taintedVars.add(node.left.name);
            }
            if (node.left.type === 'MemberExpression') {
              const prop = node.left.property?.name || node.left.property?.value;
              if (['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'dangerouslySetInnerHTML'].includes(prop) && isSource(node.right)) {
                findings.push({
                  url: targetUrl,
                  type: 'DOM-Based XSS (AST Data Flow)',
                  severity: 'High',
                  confidence: 'High',
                  poc: `Sink: ${prop} assigned with tainted data`,
                  explanation: `Static AST analysis traced data flow from a user-controllable source (e.g., location.search) directly to a dangerous DOM sink (${prop}) without sanitization.`,
                  mitigation: 'Avoid using dangerous sinks like innerHTML with user-controllable data. Use textContent or safe DOM manipulation methods.'
                });
              }
            }
          },
          CallExpression(node: any) {
            if (node.callee.type === 'Identifier') {
              if (['eval', 'setTimeout', 'setInterval'].includes(node.callee.name) && node.arguments.length > 0 && isSource(node.arguments[0])) {
                findings.push({
                  url: targetUrl,
                  type: 'DOM-Based XSS (AST Data Flow)',
                  severity: 'High',
                  confidence: 'High',
                  poc: `Sink: ${node.callee.name}() called with tainted data`,
                  explanation: `Static AST analysis traced data flow from a user-controllable source directly to a dangerous execution sink (${node.callee.name}).`,
                  mitigation: 'Never pass user-controllable strings to eval(), setTimeout(), or setInterval().'
                });
              }
            } else if (node.callee.type === 'MemberExpression') {
              const objName = node.callee.object?.name;
              const propName = node.callee.property?.name || node.callee.property?.value;
              if (objName === 'document' && ['write', 'writeln'].includes(propName) && node.arguments.length > 0 && isSource(node.arguments[0])) {
                 findings.push({
                   url: targetUrl,
                   type: 'DOM-Based XSS (AST Data Flow)',
                   severity: 'High',
                   confidence: 'High',
                   poc: `Sink: document.${propName}() called with tainted data`,
                   explanation: `Static AST analysis traced data flow from a user-controllable source directly to a dangerous DOM sink (document.${propName}).`,
                   mitigation: 'Avoid using document.write() with user-controllable data.'
                 });
              }
              if (['html', 'insertAdjacentHTML'].includes(propName) && node.arguments.length > 0 && isSource(node.arguments[0])) {
                 findings.push({
                   url: targetUrl,
                   type: 'DOM-Based XSS (AST Data Flow)',
                   severity: 'High',
                   confidence: 'High',
                   poc: `Sink: ${propName}() called with tainted data`,
                   explanation: `Static AST analysis traced data flow from a user-controllable source directly to a dangerous DOM sink (${propName}).`,
                   mitigation: `Avoid passing user-controllable data to ${propName}().`
                 });
              }
            }
          }
        });
      } catch (e) { /* ignore parse errors */ }
    }
  } catch (e) { /* ignore cheerio errors */ }
  
  // Deduplicate findings
  return Array.from(new Map(findings.map(item => [item.poc, item])).values());
}
