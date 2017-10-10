<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:foo="http://www.foo.org/" xmlns:bar="http://www.bar.org">
<!--
Attack types values:
* Information Leakage - SSN
* Predictable Resource Location
* XPath Injection
* Set-Cookie does not use HTTPOnly keyword
* Form caching detected
* Path Traversal Apache Relative Path
* Open redirect
* Login brute force
* Mixed content found
* Unsafe CORS configuration
* Information Leakage - Credit Card
* Set-Cookie does not use Secure keyword
* Clickjacking
* Parameter pollution allowed
* Path Traversal Windows Relative Path
* Command Execution
* Slow HTTP headers
* Autocomplete not disabled on login form
* HTTP Response Splitting
* Secure Cookie set by Insecure Connection
* Logins sent over unencrypted
* Cross-site Request Forgery
* Path Traversal
* SQL-Injection
* Cross Site Scripting (XSS)
* Slow HTTP body
* Path Traversal Unix Relative Path
* Large request body allowed
* Weak clientaccesspolicy.xml or crossdomain.xml policy
* Forceful Browsing
* HTTP Request Smuggling Attack
* Non-browser client
* Denial of Service
* Server Side Code Injection
* Directory Indexing
* Abuse of Functionality
* Other Application Attacks
* Other Application Activity
* Injection Attempt
* GWT Parser Attack
* Parameter Tampering
* Vulnerability Scan
* HTTP Parser Attack
* JSON Parser Attack
* LDAP Injection
* Remote File Include
* Trojan/Backdoor/Spyware
* Web Scraping
* Malicious File Upload
* Brute Force Attack
* WebSocket Parser Attack
* XML Parser Attack
* Authentication/Authorization Attacks
* Session Hijacking
* Cache Poisoning
* Information Leakage
* Buffer Overflow
* Detection Evasion
-->
<xsl:template match="/">
  <scanner_vulnerabilities>
    <xsl:variable name="URI" select="//tag[@name='host-fqdn']"/>
      <xsl:for-each select="//ReportItem">
        <vulnerability>
          <xsl:variable name="Attack" select="current()/plugin_name"/>
          <xsl:choose>
            <xsl:when test="contains($Attack, 'XML Injection')">
              <attack_type>XML Injection</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Accessible Backups')">
              <attack_type>Predictable Resource Location</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Server robots.txt Information Disclosure')">
              <attack_type>Predictable Resource Location</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attackm 'CGI Generic Tests Load Estimation (all tests)')">
              <attack_type>Vulnerability Scan</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'HTML Injections')">
              <attack_type>Injection Attempt</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'CGI Generic Injectable Parameter')">
              <attack_type>Injection Attemp</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'HTTP Methods Allowed')">
              <attack_type>Other Application Attacks</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'XSS')">
              <attack_type>Cross Site Scripting (XSS)</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Cookie Injection')">
              <attack_type>Injection Attempt</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'HyperText Transfer Protocol (HTTP) Information')">
              <attack_type>Information Leakage</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'HSTS')">
              <attack_type>Other Application Attacks</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'HTTP Server Type and Version')">
              <attack_type>Information Leakage</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Server Allows Password Auto-Completion')">
              <attack_type>Autocomplete not disabled on login form</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Application Sitemap')">
              <attack_type>Predictable Resource Location</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Clickjacking')">
              <attack_type>Clickjacking</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Missing or Permissive X-Frame-Options HTTP Response Header')">
              <attack_type>Other Application Attacks</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web mirroring')">
              <attack_type>Web Scraping</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Server Directory Enumeration')">
              <attack_type>Path Traversal</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'SSL')">
              <attack_type>Other Application Attacks</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'TLS')">
              <attack_type>Other Application Attacks</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Service Detection')">
              <attack_type>Information Leakage</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'SYN')">
              <attack_type>Denial of Service</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'CGI Generic Injectable Parameter')">
              <attack_type>Parameter pollution allowed</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Server Transmits Cleartext Credentials')">
              <attack_type>Logins sent over unencrypted</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Application Cookies Not Marked Secure')">
              <attack_type>Set-Cookie does not use Secure keyword</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Web Application Cookies Not Marked HttpOnly')">
              <attack_type>Set-Cookie does not use HTTPOnly keyword</attack_type>
            </xsl:when>
            <xsl:otherwise>
              <attack_type>Other Application Attacks</attack_type>
          </xsl:otherwise>
          </xsl:choose>
          <name><xsl:value-of select="plugin_name"/></name>
          <url><xsl:value-of select="$URI"/></url>
          <parameter><xsl:value-of select="plugin_output"/></parameter>
          <cookie></cookie>
          <xsl:variable name="risk" select="risk_factor"/>
          <xsl:choose>
            <xsl:when test="$risk='None'">
              <threat>Info</threat>
            </xsl:when>
            <xsl:otherwise>
                <threat><xsl:value-of select="risk_factor"/></threat>
              </xsl:otherwise>
          </xsl:choose>
          <score><xsl:value-of select="cvss_base_score"/></score>
          <severity><xsl:value-of select="./@severity"/></severity>
          <status>open</status>
          <opened>1</opened>
      </vulnerability>
      </xsl:for-each>
    </scanner_vulnerabilities>
</xsl:template>
</xsl:stylesheet>
