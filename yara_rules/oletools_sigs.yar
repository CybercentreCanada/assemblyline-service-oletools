rule mraptor_oletools {
    meta:
        rule_group = "technique"
        technique = "Macros suspicious properties"

        description = "Macros with AutoExec and (Write or Execute) properties"
        id = "CSE_910000"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.6"

        source = "OLETools MacroRaptor (decalage.info)"
        al_status = "DEPLOYED"
        al_score = "500"

    strings:

        //Detects common VBA strings
        $cs1 = "CreateObject"  nocase
        $cs2 = "WScript"  nocase
        $cs3 = "End Sub" fullword  nocase
        $cs4 = /Sub Auto[_]?Open/  nocase
        $macros = "Attribute VB_"
        //pcode dump
        $pcode = "Module streams:"
        //Suspicious strings RE mraptor
        $auto = /\b(Auto(Exec|_?Open|_?Close|Exit|New)|Document(_?Open|_Close|_?BeforeClose|Change|_New)|NewDocument|Workbook(_Open|_Activate|_Close)|\w+_(Painted|Painting|GotFocus|LostFocus|MouseHover|Layout|Click|Change|Resize|BeforeNavigate2|BeforeScriptExecute|DocumentComplete|DownloadBegin|DownloadComplete|FileDownload|NavigateComplete2|NavigateError|ProgressChange|PropertyChange|SetSecureLockIcon|StatusTextChange|TitleChange|MouseMove|MouseEnter|MouseLeave))\b/ nocase
        $write1 = /\b(Kill|ADODB\.Stream|WriteText|SaveAs|SaveAsRTF|SaveSetting|SetAttr)\b/ nocase
        $write2 = /\bOpen\b[^\n]+\b(Write|Append|Binary|Output|Random)\b/
        $execute1 = /(\bDeclare\b[^\n]+\bLib\b)/
        $execute2 = /\b(CreateObject|GetObject|SendKeys|MacScript)\b/ nocase
        $execute3 = /\b(S[hel]{4}|h[Sel]{4}|e[Shl]{4}|l[She]{4})\b/ nocase
        //Separate strings that should always be flagged
        $sus_write = /\b(FileCopy|CopyFile|CreateTextFile|VirtualAlloc|RtlMoveMemory|URLDownloadToFileA?|AltStartupPath|SaveToFile|FileSaveAs|MkDir|RmDir)\b/ nocase
        $sus_execute = /\b(FollowHyperlink|CreateThread|ShellExecute)\b/

    condition:
        ((2 of ($cs*) or $macros or $pcode at 0 or al_tag contains "vbs")) and (any of ($sus*) or ($auto and (any of ($write*) or any of ($execute*))))
 }

rule powershell_download {
    meta:
        rule_group = "technique"
        technique = "Powershell download"

        description = "Using Powershell to download content"
        id = "CSE_910001"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.6"

        al_status = "DEPLOYED"
        al_score = "500"

    strings:
        $pwrsh = "powershell" nocase
        $web1 = "Invoke-WebRequest" nocase
        $web2 = "Net.WebClient" nocase
        $web3 = "Net.WebRequest"
        $web4 = "DownloadFile" nocase
        $web5 = "DownloadString"
		$web6 = "BitsTransfer" nocase

    condition:
        $pwrsh and any of ($web*)
}

rule VBA_external_connections {
    meta:
        rule_group = "technique"
        technique = "External connections via VB script"

        description = "Strings in VB script that suggest external connections"
        id = "CSE_910002"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.6"

        al_status = "DEPLOYED"
        al_score = "500"

    strings:
        //Detect common VBA strings
        $cs1 = "CreateObject" nocase
        $cs2 = "WScript" nocase
        $cs3 = "End Sub" fullword nocase
        $cs4 = /Sub Auto[_]?(Open|Close)/ nocase
        $macros = "Attribute VB_"
        //pcode dump
        $pcode = "Module streams:"
        //External connections
        $ex1 = "ConnectServer" nocase
        $ex2 = "InternetCloseHandle" nocase
        $ex3 = "InternetExplorerApplication" nocase
        $ex4 = "InternetOpenUrl" nocase
        $ex5 = "InternetReadFile" nocase
        $ex6 = "SetRequestHeader" nocase
        $ex7 = "User-Agent" nocase
		$ex8 = "wininet.dll" nocase
        $ex9reg = /http[s]?:\/\//

    condition:
        (2 of ($cs*) or $macros or $pcode at 0 or al_tag contains "vbs") and any of ($ex*)
}

/*
  MODIFIED BY CSE
  Version 0.0.1 2017/03/05
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk
  These are YARA rules to detect VBA code that might be malware.
  History:
    2017/03/05: start
*/

rule VBA_CallByName
{
    meta:
        rule_group = "technique"
        technique = "CallbyName Function"

        description = "Executes a method of an object, or sets or returns a property of an object"
        id = "CSE_910003"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.6"
        source = "Didier Stevens (github)"

        al_status = "DEPLOYED"
        al_score = "500"

    strings:
        //Detects common VBA strings
        $cs1 = "CreateObject"  nocase
        $cs2 = "WScript"  nocase
        $cs3 = "End Sub" fullword  nocase
        $cs4 = /Sub Auto[_]?Open/  nocase
        $macros = "Attribute VB_"
        //pcode dump
        $pcode = "Module streams:"
        // Suspicious Function
        $s = "CallByName" nocase fullword
    condition:
        (2 of ($cs*) or $macros or $pcode at 0 or al_tag contains "vbs") and any of ($s*)
}