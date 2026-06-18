// Default vulnerability checklist, derived from the OWASP Web Security Testing
// Guide (WSTG). A copy of this list is embedded into every new project so the
// auditor can track status per engagement.
//
// IDs and titles follow the OWASP WSTG (stable). Codes are kept in the 2-digit
// format historically used by this app so existing catalogs stay compatible.
// A complementary "API (OWASP API Security Top 10)" section is appended — it is
// not part of WSTG but is commonly used alongside it during web/API audits.
//
// Reference: https://owasp.org/www-project-web-security-testing-guide/

const wstgTemplate = [
  // --- Information Gathering (WSTG-INFO) ---
  { code: 'WSTG-INFO-01', category: 'Information Gathering', name: 'Conduct search engine discovery reconnaissance for information leakage', description: 'Look for sensitive information indexed by search engines (Google dorks, cached pages).' },
  { code: 'WSTG-INFO-02', category: 'Information Gathering', name: 'Fingerprint web server', description: 'Identify the web server software and version.' },
  { code: 'WSTG-INFO-03', category: 'Information Gathering', name: 'Review webserver metafiles for information leakage', description: 'robots.txt, sitemap.xml, security.txt, humans.txt and other metafiles.' },
  { code: 'WSTG-INFO-04', category: 'Information Gathering', name: 'Enumerate applications on webserver', description: 'Find apps/vhosts/virtual directories hosted on the same server.' },
  { code: 'WSTG-INFO-05', category: 'Information Gathering', name: 'Review webpage content for information leakage', description: 'Comments, metadata, hidden fields, JS source maps, secrets in client code.' },
  { code: 'WSTG-INFO-06', category: 'Information Gathering', name: 'Identify application entry points', description: 'Enumerate request/response parameters, headers and injection points.' },
  { code: 'WSTG-INFO-07', category: 'Information Gathering', name: 'Map execution paths through application', description: 'Spider and understand all reachable functions and flows.' },
  { code: 'WSTG-INFO-08', category: 'Information Gathering', name: 'Fingerprint web application framework', description: 'Identify the framework/CMS and its version.' },
  { code: 'WSTG-INFO-09', category: 'Information Gathering', name: 'Fingerprint web application', description: 'Identify the specific application/product in use.' },
  { code: 'WSTG-INFO-10', category: 'Information Gathering', name: 'Map application architecture', description: 'Identify components, WAFs, CDNs, proxies, microservices and trust boundaries.' },

  // --- Configuration & Deployment Management (WSTG-CONF) ---
  { code: 'WSTG-CONF-01', category: 'Configuration Management', name: 'Test network infrastructure configuration', description: 'Review exposed services and infrastructure configuration.' },
  { code: 'WSTG-CONF-02', category: 'Configuration Management', name: 'Test application platform configuration', description: 'Default files, sample apps, debug modes, framework hardening.' },
  { code: 'WSTG-CONF-03', category: 'Configuration Management', name: 'Test file extensions handling for sensitive information', description: 'Extension handling revealing source or config (.inc, .bak, .config…).' },
  { code: 'WSTG-CONF-04', category: 'Configuration Management', name: 'Review old backup and unreferenced files for sensitive information', description: 'Backups, .bak/.old, temp files, source disclosure.' },
  { code: 'WSTG-CONF-05', category: 'Configuration Management', name: 'Enumerate infrastructure and application admin interfaces', description: 'Locate management/admin consoles and hidden interfaces.' },
  { code: 'WSTG-CONF-06', category: 'Configuration Management', name: 'Test HTTP methods', description: 'Dangerous methods (PUT, DELETE, TRACE, CONNECT) and verb handling.' },
  { code: 'WSTG-CONF-07', category: 'Configuration Management', name: 'Test HTTP Strict Transport Security (HSTS)', description: 'Verify the HSTS header is present, correct and applied.' },
  { code: 'WSTG-CONF-08', category: 'Configuration Management', name: 'Test RIA cross domain policy', description: 'Review crossdomain.xml / clientaccesspolicy.xml.' },
  { code: 'WSTG-CONF-09', category: 'Configuration Management', name: 'Test file permission', description: 'Review file/directory permissions on sensitive resources.' },
  { code: 'WSTG-CONF-10', category: 'Configuration Management', name: 'Test for subdomain takeover', description: 'Dangling DNS records pointing to unclaimed services.' },
  { code: 'WSTG-CONF-11', category: 'Configuration Management', name: 'Test cloud storage', description: 'Check S3/blob/bucket permissions and exposure.' },
  { code: 'WSTG-CONF-12', category: 'Configuration Management', name: 'Test for Content Security Policy (CSP)', description: 'Presence and robustness of the CSP header.' },

  // --- Identity Management (WSTG-IDNT) ---
  { code: 'WSTG-IDNT-01', category: 'Identity Management', name: 'Test role definitions', description: 'Review defined roles and their mapping to permissions.' },
  { code: 'WSTG-IDNT-02', category: 'Identity Management', name: 'Test user registration process', description: 'Registration controls and abuse cases.' },
  { code: 'WSTG-IDNT-03', category: 'Identity Management', name: 'Test account provisioning process', description: 'How accounts are created and de-provisioned.' },
  { code: 'WSTG-IDNT-04', category: 'Identity Management', name: 'Testing for account enumeration and guessable user account', description: 'Username/email enumeration vectors.' },
  { code: 'WSTG-IDNT-05', category: 'Identity Management', name: 'Testing for weak or unenforced username policy', description: 'Predictable or guessable usernames.' },

  // --- Authentication (WSTG-ATHN) ---
  { code: 'WSTG-ATHN-01', category: 'Authentication', name: 'Testing for credentials transported over an encrypted channel', description: 'Ensure credentials are never sent in clear text.' },
  { code: 'WSTG-ATHN-02', category: 'Authentication', name: 'Testing for default credentials', description: 'Test for default/known accounts and passwords.' },
  { code: 'WSTG-ATHN-03', category: 'Authentication', name: 'Testing for weak lock out mechanism', description: 'Brute-force protection / account lockout / rate limiting.' },
  { code: 'WSTG-ATHN-04', category: 'Authentication', name: 'Testing for bypassing authentication schema', description: 'Forced browsing, parameter tampering, direct page request.' },
  { code: 'WSTG-ATHN-05', category: 'Authentication', name: 'Testing for vulnerable remember password', description: 'Insecure "remember me" / persistent auth tokens.' },
  { code: 'WSTG-ATHN-06', category: 'Authentication', name: 'Testing for browser cache weaknesses', description: 'Sensitive data cached / retrievable after logout.' },
  { code: 'WSTG-ATHN-07', category: 'Authentication', name: 'Testing for weak password policy', description: 'Length, complexity and common-password checks.' },
  { code: 'WSTG-ATHN-08', category: 'Authentication', name: 'Testing for weak security question answer', description: 'Guessable / researchable security questions.' },
  { code: 'WSTG-ATHN-09', category: 'Authentication', name: 'Testing for weak password change or reset functionalities', description: 'Reset token predictability, host header poisoning, missing checks.' },
  { code: 'WSTG-ATHN-10', category: 'Authentication', name: 'Testing for weaker authentication in alternative channel', description: 'Mobile/API/legacy endpoints with weaker auth.' },

  // --- Authorization (WSTG-ATHZ) ---
  { code: 'WSTG-ATHZ-01', category: 'Authorization', name: 'Testing directory traversal / file include', description: 'Path traversal and LFI/RFI.' },
  { code: 'WSTG-ATHZ-02', category: 'Authorization', name: 'Testing for bypassing authorization schema', description: 'Access resources without proper rights.' },
  { code: 'WSTG-ATHZ-03', category: 'Authorization', name: 'Testing for privilege escalation', description: 'Vertical privilege escalation.' },
  { code: 'WSTG-ATHZ-04', category: 'Authorization', name: 'Testing for Insecure Direct Object References (IDOR)', description: 'Horizontal access to other users’ objects.' },
  { code: 'WSTG-ATHZ-05', category: 'Authorization', name: 'Testing for OAuth weaknesses', description: 'OAuth/OIDC flow, redirect_uri, scope and token handling issues.' },

  // --- Session Management (WSTG-SESS) ---
  { code: 'WSTG-SESS-01', category: 'Session Management', name: 'Testing for session management schema', description: 'Token randomness, predictability and lifecycle.' },
  { code: 'WSTG-SESS-02', category: 'Session Management', name: 'Testing for cookies attributes', description: 'Secure, HttpOnly, SameSite, scope and expiry flags.' },
  { code: 'WSTG-SESS-03', category: 'Session Management', name: 'Testing for session fixation', description: 'Session ID not rotated on authentication.' },
  { code: 'WSTG-SESS-04', category: 'Session Management', name: 'Testing for exposed session variables', description: 'Session IDs in URLs, logs or referrers.' },
  { code: 'WSTG-SESS-05', category: 'Session Management', name: 'Testing for Cross-Site Request Forgery (CSRF)', description: 'State-changing actions without anti-CSRF protection.' },
  { code: 'WSTG-SESS-06', category: 'Session Management', name: 'Testing for logout functionality', description: 'Server-side session invalidation on logout.' },
  { code: 'WSTG-SESS-07', category: 'Session Management', name: 'Testing session timeout', description: 'Idle and absolute timeouts enforced server-side.' },
  { code: 'WSTG-SESS-08', category: 'Session Management', name: 'Testing for session puzzling', description: 'Session variable overloading across flows.' },
  { code: 'WSTG-SESS-09', category: 'Session Management', name: 'Testing for session hijacking', description: 'Token theft / replay and binding weaknesses.' },
  { code: 'WSTG-SESS-10', category: 'Session Management', name: 'Testing JSON Web Tokens (JWT)', description: 'alg=none, weak keys, signature bypass, missing exp/aud validation.' },

  // --- Input Validation (WSTG-INPV) ---
  { code: 'WSTG-INPV-01', category: 'Input Validation', name: 'Testing for reflected Cross-Site Scripting (XSS)', description: 'Reflected user input executed in the browser.' },
  { code: 'WSTG-INPV-02', category: 'Input Validation', name: 'Testing for stored Cross-Site Scripting (XSS)', description: 'Persisted payloads executed for other users.' },
  { code: 'WSTG-INPV-03', category: 'Input Validation', name: 'Testing for HTTP verb tampering', description: 'Method-based access bypass.' },
  { code: 'WSTG-INPV-04', category: 'Input Validation', name: 'Testing for HTTP parameter pollution', description: 'Duplicate parameters changing behaviour.' },
  { code: 'WSTG-INPV-05', category: 'Input Validation', name: 'Testing for SQL injection', description: 'Classic, blind and time-based SQLi (and NoSQL operator injection).' },
  { code: 'WSTG-INPV-06', category: 'Input Validation', name: 'Testing for LDAP injection', description: 'LDAP filter/DN injection.' },
  { code: 'WSTG-INPV-07', category: 'Input Validation', name: 'Testing for XML injection (incl. XXE)', description: 'XML injection and XML External Entity processing.' },
  { code: 'WSTG-INPV-08', category: 'Input Validation', name: 'Testing for SSI injection', description: 'Server-Side Includes injection.' },
  { code: 'WSTG-INPV-09', category: 'Input Validation', name: 'Testing for XPath injection', description: 'XPath query injection.' },
  { code: 'WSTG-INPV-10', category: 'Input Validation', name: 'Testing for IMAP/SMTP injection', description: 'Mail command injection via input.' },
  { code: 'WSTG-INPV-11', category: 'Input Validation', name: 'Testing for code injection', description: 'Server-side code execution via input.' },
  { code: 'WSTG-INPV-12', category: 'Input Validation', name: 'Testing for command injection', description: 'OS command execution via input.' },
  { code: 'WSTG-INPV-13', category: 'Input Validation', name: 'Testing for format string injection', description: 'Format string vulnerabilities.' },
  { code: 'WSTG-INPV-14', category: 'Input Validation', name: 'Testing for incubated vulnerability', description: 'Stored/incubated payloads triggered later.' },
  { code: 'WSTG-INPV-15', category: 'Input Validation', name: 'Testing for HTTP splitting / smuggling', description: 'Request smuggling and response splitting.' },
  { code: 'WSTG-INPV-16', category: 'Input Validation', name: 'Testing for HTTP incoming requests', description: 'Inspect and tamper with raw incoming requests.' },
  { code: 'WSTG-INPV-17', category: 'Input Validation', name: 'Testing for host header injection', description: 'Host header manipulation (cache poisoning, password reset).' },
  { code: 'WSTG-INPV-18', category: 'Input Validation', name: 'Testing for Server-Side Template Injection (SSTI)', description: 'Template engine expression injection.' },
  { code: 'WSTG-INPV-19', category: 'Input Validation', name: 'Testing for Server-Side Request Forgery (SSRF)', description: 'App fetching attacker-controlled URLs.' },

  // --- Error Handling (WSTG-ERRH) ---
  { code: 'WSTG-ERRH-01', category: 'Error Handling', name: 'Testing for improper error handling', description: 'Verbose errors leaking internal details.' },
  { code: 'WSTG-ERRH-02', category: 'Error Handling', name: 'Testing for stack traces', description: 'Detailed traces revealing internals.' },

  // --- Cryptography (WSTG-CRYP) ---
  { code: 'WSTG-CRYP-01', category: 'Cryptography', name: 'Testing for weak transport layer security', description: 'TLS protocols, ciphers, certificate validity.' },
  { code: 'WSTG-CRYP-02', category: 'Cryptography', name: 'Testing for padding oracle', description: 'Padding oracle attacks.' },
  { code: 'WSTG-CRYP-03', category: 'Cryptography', name: 'Testing for sensitive information sent via unencrypted channels', description: 'Cleartext transmission of sensitive data.' },
  { code: 'WSTG-CRYP-04', category: 'Cryptography', name: 'Testing for weak encryption', description: 'Weak algorithms, key management, missing salting.' },

  // --- Business Logic (WSTG-BUSL) ---
  { code: 'WSTG-BUSL-01', category: 'Business Logic', name: 'Test business logic data validation', description: 'Logic-layer validation bypass.' },
  { code: 'WSTG-BUSL-02', category: 'Business Logic', name: 'Test ability to forge requests', description: 'Forge/replay requests outside the intended flow.' },
  { code: 'WSTG-BUSL-03', category: 'Business Logic', name: 'Test integrity checks', description: 'Tamper with hidden/derived values.' },
  { code: 'WSTG-BUSL-04', category: 'Business Logic', name: 'Test for process timing', description: 'Race conditions / TOCTOU.' },
  { code: 'WSTG-BUSL-05', category: 'Business Logic', name: 'Test number of times a function can be used limits', description: 'Bypass of usage/quantity limits.' },
  { code: 'WSTG-BUSL-06', category: 'Business Logic', name: 'Testing for the circumvention of work flows', description: 'Skip steps in multi-stage workflows.' },
  { code: 'WSTG-BUSL-07', category: 'Business Logic', name: 'Test defenses against application misuse', description: 'Detection/throttling of abusive behaviour.' },
  { code: 'WSTG-BUSL-08', category: 'Business Logic', name: 'Test upload of unexpected file types', description: 'Upload of disallowed/unexpected file types.' },
  { code: 'WSTG-BUSL-09', category: 'Business Logic', name: 'Test upload of malicious files', description: 'Upload of malicious files (web shells, polyglots).' },

  // --- Client-Side (WSTG-CLNT) ---
  { code: 'WSTG-CLNT-01', category: 'Client-Side', name: 'Testing for DOM-based Cross-Site Scripting', description: 'Client-side sinks executing input.' },
  { code: 'WSTG-CLNT-02', category: 'Client-Side', name: 'Testing for JavaScript execution', description: 'Injection of JavaScript executed by the client.' },
  { code: 'WSTG-CLNT-03', category: 'Client-Side', name: 'Testing for HTML injection', description: 'Markup injection into the DOM.' },
  { code: 'WSTG-CLNT-04', category: 'Client-Side', name: 'Testing for client-side URL redirect (open redirect)', description: 'Unvalidated client-side redirects.' },
  { code: 'WSTG-CLNT-05', category: 'Client-Side', name: 'Testing for CSS injection', description: 'Injection into client-side CSS.' },
  { code: 'WSTG-CLNT-06', category: 'Client-Side', name: 'Testing for client-side resource manipulation', description: 'Manipulation of client-controlled resource references.' },
  { code: 'WSTG-CLNT-07', category: 'Client-Side', name: 'Testing Cross-Origin Resource Sharing (CORS)', description: 'Overly permissive CORS policy.' },
  { code: 'WSTG-CLNT-08', category: 'Client-Side', name: 'Testing for cross site flashing', description: 'Flash-based cross-site issues.' },
  { code: 'WSTG-CLNT-09', category: 'Client-Side', name: 'Testing for clickjacking', description: 'Missing frame-busting / X-Frame-Options / CSP frame-ancestors.' },
  { code: 'WSTG-CLNT-10', category: 'Client-Side', name: 'Testing WebSockets', description: 'Origin checks and message validation.' },
  { code: 'WSTG-CLNT-11', category: 'Client-Side', name: 'Testing web messaging (postMessage)', description: 'Origin validation on message handlers.' },
  { code: 'WSTG-CLNT-12', category: 'Client-Side', name: 'Testing browser storage', description: 'Sensitive data in localStorage/sessionStorage/IndexedDB.' },
  { code: 'WSTG-CLNT-13', category: 'Client-Side', name: 'Testing for Cross Site Script Inclusion (XSSI)', description: 'Leaking data via cross-site script inclusion.' },

  // --- API (WSTG-APIT) ---
  { code: 'WSTG-APIT-01', category: 'API (WSTG)', name: 'Testing GraphQL', description: 'Introspection, injection, batching/DoS and authorization on GraphQL.' },

  // --- Complementary: OWASP API Security Top 10 (not part of WSTG) ---
  { code: 'API-01', category: 'API (OWASP API Top 10)', name: 'Broken object level authorization (BOLA)', description: 'API IDOR on object IDs.' },
  { code: 'API-02', category: 'API (OWASP API Top 10)', name: 'Broken authentication', description: 'Weak API auth / token handling.' },
  { code: 'API-03', category: 'API (OWASP API Top 10)', name: 'Broken object property level authorization', description: 'Excessive data exposure / mass assignment.' },
  { code: 'API-04', category: 'API (OWASP API Top 10)', name: 'Unrestricted resource consumption', description: 'No throttling / rate limiting on API endpoints.' },
  { code: 'API-05', category: 'API (OWASP API Top 10)', name: 'Broken function level authorization', description: 'Privileged API actions reachable by lower-privileged users.' },
  { code: 'API-06', category: 'API (OWASP API Top 10)', name: 'Unrestricted access to sensitive business flows', description: 'Automated abuse of sensitive flows.' },
  { code: 'API-07', category: 'API (OWASP API Top 10)', name: 'Server-Side Request Forgery (SSRF)', description: 'API fetching attacker-controlled URLs.' },
  { code: 'API-08', category: 'API (OWASP API Top 10)', name: 'Security misconfiguration', description: 'Verbose errors, default configs, missing headers.' },
  { code: 'API-09', category: 'API (OWASP API Top 10)', name: 'Improper inventory management', description: 'Shadow / old API versions exposed.' },
  { code: 'API-10', category: 'API (OWASP API Top 10)', name: 'Unsafe consumption of APIs', description: 'Blind trust of data from third-party APIs.' },
];

const OWASP_BASE = 'https://owasp.org/www-project-web-security-testing-guide/';

// Attach a default reference URL where not set.
function getChecklistTemplate() {
  return wstgTemplate.map((item) => ({
    ...item,
    reference: item.reference || OWASP_BASE,
    command: item.command || '',
    notes: item.notes || '',
    verified: false,
    vulnerable: null,
  }));
}

module.exports = { getChecklistTemplate, wstgTemplate };
