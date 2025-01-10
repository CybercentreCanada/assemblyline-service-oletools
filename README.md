[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_oletools-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-oletools)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-oletools)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-oletools)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-oletools)](./LICENSE)
# Oletools Service

This Assemblyline service extracts metadata and network information, and reports on anomalies in Microsoft OLE and XML documents using the Python library py-oletools and hachoir.

## Service Details

### Configuration Parameters (set by administrator):

- MACRO_SCORE_MAX_FILE_SIZE: A macros section will not be flagged in results if the size is greater than this value.
(Default value: 5 * 1024**2)
- MACRO_SCORE_MIN_ALERT: Chains.json contains common English trigraphs. We score macros on how common these trigraphs
appear in code, skipping over some common keywords. A lower score than this config value indicates more randomized text,
and random variable/function names are common in malicious macros. (Default value: 0.6)
- METADATA_SIZE_TO_EXTRACT: If OLE metadata is larger than this size (in bytes), the service will extract the metadata content as a new file (Default value: 500)
- IOC_PATTERN_SAFELIST: If an IOC contains one of the strings in the list, Oletools will ignore it unless in deep scan mode. (Default value: [])
- IOC_EXACT_SAFELIST: If an IOC is one of the strings in the list, Oletools will ignore it unless in deep scan mode. (Default value: [])

### Execution

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


## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Oletools \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-oletools

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Oletools

Ce service Assemblyline extrait des métadonnées et des informations sur le réseau, et signale les anomalies dans les documents Microsoft OLE et XML à l'aide des bibliothèques Python py-oletools et hachoir.

## Détails du service

### Paramètres de configuration (définis par l'administrateur) :

- MACRO_SCORE_MAX_FILE_SIZE : Une section de macros ne sera pas signalée dans les résultats si sa taille est supérieure à cette valeur.
(Valeur par défaut : 5 * 1024**2)
- MACRO_SCORE_MIN_ALERT : Chains.json contient des trigraphes anglais courants. Nous évaluons les macros en fonction de la fréquence d'apparition de ces trigraphes dans le code, en ignorant certains mots-clés courants. Un score inférieur à cette valeur indique un texte plus aléatoire, et les noms de variables/fonctions aléatoires sont fréquents dans les macros malveillantes. (Valeur par défaut : 0.6)
- METADATA_SIZE_TO_EXTRACT : Si les métadonnées OLE dépassent cette taille (en octets), le service extrait le contenu des métadonnées dans un nouveau fichier (valeur par défaut : 500).
- IOC_PATTERN_SAFELIST : Si un IOC contient l'une des chaînes de la liste, Oletools l'ignorera à moins d'être en mode d'analyse approfondie. (Valeur par défaut : [])
- IOC_EXACT_SAFELIST : Si un IOC est l'une des chaînes de la liste, Oletools l'ignorera à moins qu'il ne soit en mode d'analyse approfondie. (Valeur par défaut : [])

### Exécution

Le service Oletools signale les informations suivantes pour chaque fichier lorsqu'il est présent :

1. Macros individuelles : (AL TAG : technique.macro)
    * SHA256 de chaque section. (AL TAG : file.ole.macro.sha256)
    * Chaînes suspectes. (AL TAG : file.ole.macro.suspicious_strings)
    * Indicateurs de réseau.

2. Flux de documents intégrés et informations OLE :
    * Nom et métadonnées (auteur, société, dernière heure de sauvegarde, etc.).
    AL TAGS :

            file.ole.summary.title,
            file.ole.summary.subject,
            file.ole.summary.author,
            fichier.ole.sommaire.commentaire,
            fichier.ole.summary.last_saved_by,
            file.ole.summary.last_printed,
            file.ole.summary.create_time,
            file.ole.summary.last_saved_time,
            file.ole.summary.manager,
            fichier.ole.summary.company,
            file.ole.summary.codepage

    * CLSIDs (drapeaux de valeurs malveillantes connues). (AL TAG : file.ole.clsid)

3. Caractéristiques des flux XML/OLE suspects :
    * FrankenStrings IOC Patterns résultats du module.
    * Contenu Adobe Flash.
    * Contenu codé en Base64.
    * Contenu codé en hexadécimal.

4. Liens DDE MSO (AL TAG : file.ole.dde_link)

5. Possibilité d'utilisation de VBA. Déterminé lorsqu'il existe une différence de contenu suspect entre le dump macro et le dump pcode.

6. Le service extrait :
    * Tout le contenu des macros.
    * Tout le contenu du pcode.
    * Les flux OLE et xml suspects.
    * Liens DDE

7. En mode d'analyse approfondie, tous les flux OLE seront extraits et hachoir effectuera une analyse approfondie des objets.


## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Oletools \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-oletools

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
