<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:foo="http://www.foo.org/" xmlns:bar="http://www.bar.org">
<xsl:template match="/">
  <scanner_vulnerabilities>
    <xsl:variable name="URI" select="//tag[@name='host-fqdn']"/>
      <xsl:for-each select="//ReportItem">
        <vulnerability>
          <attack_type>Other Application Attacks</attack_type>
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
