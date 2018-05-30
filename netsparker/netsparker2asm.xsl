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
    <!-- Netsparker has the URL in each Vulnerability <xsl:variable name="URI" select="//tag[@name='host-fqdn']"/> -->
      <xsl:for-each select="//vulnerability">
        <vulnerability>
          <xsl:variable name="Attack" select="current()/type"/>
          <xsl:choose>
            <xsl:when test="contains($Attack, 'ConfirmedBooleanSqlInjection')">
              <attack_type>SQL-Injection</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'OpenSslOutOfDate')">
              <attack_type>Denial of Service</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'PhpOutOfDate')">
              <attack_type>Denial of Service</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'MixedContentResource')">
              <attack_type>Mixed content found</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'InsecureFrameExternal')">
              <attack_type>Mixed content found</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'AutoComplete')">
              <attack_type>Autocomplete not disabled on login form</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'CookieNotMarkedAsHttpOnly')">
              <attack_type>Set-Cookie does not use HTTPOnly keyword</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Disclosure')">
              <attack_type>Information Leakage</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'OpenRedirectInPost')">
              <attack_type>Open redirect</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Csrf')">
              <attack_type>Cross-site Request Forgery</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Xss')">
              <attack_type>Cross Site Scripting (XSS)</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'PathLeakage')">
              <attack_type>Path Traversal Unix Relative Path</attack_type>
            </xsl:when>
            <xsl:otherwise>
              <attack_type>Other Application Attacks</attack_type>
          </xsl:otherwise>
          </xsl:choose>
          <name><xsl:value-of select="type"/></name>
          <url><xsl:value-of select="url"/></url>
          <parameter><xsl:value-of select="vulnerableparametervalue"/></parameter>
          <cookie></cookie>
          <xsl:variable name="risk" select="certainty"/>
          <xsl:choose>
            <xsl:when test="$risk='None'">
              <threat>Info</threat>
            </xsl:when>
            <xsl:otherwise>
                <threat><xsl:value-of select="certainty"/></threat>
              </xsl:otherwise>
          </xsl:choose>
          <score><xsl:value-of select="current()/classification/CVSS/descendant::score[1]/value"/></score>
          <severity><xsl:value-of select="severity"/></severity>
          <status>open</status>
          <opened>1</opened>
      </vulnerability>
      </xsl:for-each>
    </scanner_vulnerabilities>
</xsl:template>
</xsl:stylesheet>
