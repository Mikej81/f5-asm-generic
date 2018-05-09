# F5 ASM Generic Scanner Translator
Generic ASM Vulnerability Schema XSLT

## Current Translations
* Nessus 6
* Netsparker
* Whitehat
* F-Secure

## Usage
Use XSLT transformation tool to convert Web Vulnerability Scan results into an ASM compatible remediation file for import.

```bash
xsltproc nessus2asm.xsl scan_results.nessus > Nessus_Import.xml
```

```bash
xsltproc netsparker2asm.xsl scan_results.xml > Netsparker_Import.xml
```

[https://devcentral.f5.com/articles/nessus-6-xslt-conversion-for-asm-generic-vulnerability-schema-27632](https://devcentral.f5.com/articles/nessus-6-xslt-conversion-for-asm-generic-vulnerability-schema-27632)

## Updates
* 10-10-2017 - Added several vulnerability mappings.  Some may have better choices, working off scan results that arent 100% comprehensive but should be a good start.
* 02-08-2018 - Added some small mappings for Whitehat scans.  Could use some tweaking but baseline is there.
* 05-09-2018 - Added F-Secure, limited mappings.  Cleaned up file names.
