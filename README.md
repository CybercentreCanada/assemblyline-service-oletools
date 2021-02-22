# Oletools Service

This Assemblyline service extracts metadata and network information, and reports on anomalies in Microsoft OLE and XML documents using the Python library py-oletools and hachoir.

**NOTE**: This service does not require you to buy a licence and is preinstalled and working after a default 
installation.

## Configuration Parameters (set by administrator):

- MACRO_SCORE_MAX_FILE_SIZE: A macros section will not be flagged in results if the size is greater than this value. 
(Default value: 5 * 1024**2)
- MACRO_SCORE_MIN_ALERT: Chains.json contains common English trigraphs. We score macros on how common these trigraphs 
appear in code, skipping over some common keywords. A lower score than this config value indicates more randomized text, 
and random variable/function names are common in malicious macros. (Default value: 0.6)
- METADATA_SIZE_TO_EXTRACT: If OLE metadata is larger than this size (in bytes), the service will extract the metadata content as a new file (Default value: 500)
- IOC_PATTERN_SAFELIST: If an IOC contains one of the strings in the list, Oletools will ignore it unless in deep scan mode. (Default value: [])
- IOC_EXACT_SAFELIST: If an IOC is one of the strings in the list, Oletools will ignore it unless in deep scan mode. (Default value: [])

## Execution

The Oletools service will report the following information for each file when present:

1. Individual Macros: (AL TAG: technique.macro)
    * SHA256 of each section. (AL TAG: file.ole.macro.sha256)
    * Suspicious strings. (AL TAG: file.ole.macro.suspicious_strings)
    * Network indicators. 

2. Embedded document streams and OLE information:
    * Name and metadata (author, company, last saved time, etc). 
    AL TAGS:
    
            file.ole.summary.title,
            file.ole.summary.subject,
            file.ole.summary.author,
            file.ole.summary.comment,
            file.ole.summary.last_saved_by,
            file.ole.summary.last_printed,
            file.ole.summary.create_time,
            file.ole.summary.last_saved_time,
            file.ole.summary.manager,
            file.ole.summary.company,
            file.ole.summary.codepage
            
    * CLSIDs (flags known malicious values). (AL TAG: file.ole.clsid)

3. Suspicious XML/OLE Stream features:
    * FrankenStrings IOC Patterns module results.
    * Adobe Flash content.
    * Base64 encoded content.
    * Hex encoded content.

4. MSO DDE Links (AL TAG: file.ole.dde_link)

5. Possible VBA stomping. Determined when difference in suspicious content exists between macro 
dump and pcode dump. 

6. Service will extract: 
    * All macros content.
    * All pcode content.
    * Suspicious OLE streams and xml.
    * DDE Links

7. If in deep scan mode, all OLE streams will be extracted and hachoir will run its deep object analysis.
