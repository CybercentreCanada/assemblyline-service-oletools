# Oletools Service

This Assemblyline service extracts metadata and network information, and reports on anomalies in Microsoft OLE and 
XML documents using the Python library py-oletools.

**NOTE**: This service does not require you to buy a licence and is preinstalled and working after a default 
installation.

## Configuration Parameters (set by administrator):

- MACRO_SCORE_MAX_FILE_SIZE: A macros section will not be flagged in results if the size is greater than this value. 
(Default value: 5 * 1024**2)
- MACRO_SCORE_MIN_ALERT: Chains.json contains common English trigraphs. We score macros on how common these trigraphs 
appear in code, skipping over some common keywords. A lower score than this config value indicates more randomized text, 
and random variable/function names are common in malicious macros. (Default value: 0.6)
- METADATA_SIZE_TO_EXTRACT: If OLE metadata is larger than this size (in bytes), the service will extract the metadata content as a new file (Default value: 500)  

## Execution

The Oletools service will report the following information for each file when present:

1. Individual Macros: (AL TAG: TECHNIQUE_MACROS)
    * SHA256 of each section. (AL TAG: OLE_MACRO_SHA256)
    * Suspicious strings. (AL TAG: OLE_MACRO_SUSPICIOUS_STRINGS)
    * Network indicators. 

2. Embedded document streams and OLE information:
    * Name and metadata (author, company, last saved time, etc). 
    AL TAGS:
    
            OLE_SUMMARY_TITLE,
            OLE_SUMMARY_SUBJECT,
            OLE_SUMMARY_AUTHOR,
            OLE_SUMMARY_COMMENTS,
            OLE_SUMMARY_LASTSAVEDBY,
            OLE_SUMMARY_LASTPRINTED,
            OLE_SUMMARY_CREATETIME,
            OLE_SUMMARY_LASTSAVEDTIME,
            OLE_SUMMARY_MANAGER,
            OLE_SUMMARY_COMPANY,
            OLE_SUMMARY_CODEPAGE
            
    * CLSIDs (flags known malicious values). (AL TAG: OLE_CLSID)

3. Suspicious XML/OLE Stream features:
    * FrankenStrings IOC Patterns module results.
    * Adobe Flash content.
    * Base64 encoded content.
    * Hex encoded content.

4. MSO DDE Links (AL TAG: OLE_DDE_LINK)

5. Service will extract: 
    * All macros content.
    * Suspicious OLE streams and xml.
    * If in deep scan mode, all OLE streams will be extracted.