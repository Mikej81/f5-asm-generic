<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:foo="http://www.foo.org/"
  xmlns:bar="http://www.bar.org/"
  xmlns:wh="http://whitehatsec.com/XML-api-Vuln">
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
<xsl:template match="wh:vulnerabilities">
  <scanner_vulnerabilities>
    <xsl:for-each select="wh:vulnerability">
              <vulnerability>
          <xsl:variable name="Attack" select="@class"/>
          <xsl:choose>
            <xsl:when test="contains($Attack, 'Brute Force')">
              <attack_type>Brute Force Attack</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Unsecured Session Cookie')">
              <attack_type>Set-Cookie does not use HTTPOnly keyword</attack_type>
            </xsl:when>
            <xsl:when test="contains($Attack, 'Information Leakage')">
              <attack_type>Information Leakage</attack_type>
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
          <Attack><xsl:value-of select="@class"/></Attack>
          <url><xsl:value-of select="@url"/></url>
          <parameter><xsl:value-of select="@service_level_abbr"/></parameter>
          <cookie></cookie>
          <xsl:variable name="risk" select="@threat"/>
          <xsl:choose>
            <xsl:when test="$risk='None'">
              <threat>Info</threat>
            </xsl:when>
            <xsl:otherwise>
                <threat><xsl:value-of select="@certainty"/></threat>
              </xsl:otherwise>
          </xsl:choose>
          <score><xsl:value-of select="current()/@score"/></score>
          <severity><xsl:value-of select="current()/@threat"/></severity>
          <status><xsl:value-of select="current()/@status"/></status>
          <opened><xsl:value-of select="current()/@opened"/></opened>
        </vulnerability>
    </xsl:for-each>
    <xsl:apply-templates/>
  </scanner_vulnerabilities>
</xsl:template>

</xsl:stylesheet>
