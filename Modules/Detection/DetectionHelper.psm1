#   This file is part of the SkyScalpel framework and is based on the
#   open-source SkyScalpel project (https://github.com/Permiso-io-tools/SkyScalpel).
#
#   Copyright 2024 Permiso Security <https://permiso.io/>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



function Find-Evil
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Find-Evil
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: Out-EvilSummary

.DESCRIPTION

Find-Evil evaluates detection rules defined in FindEvil C# method for input JSON document(s).

.PARAMETER JsonDocument

Specifies JSON document(s) against which to evaluate detection rules.

.PARAMETER Include

(Optional) Specifies detection rule(s) to include in evaluation (at the exclusion of all other rules). Can be used together with -Exclude input parameter.

.PARAMETER Exclude

(Optional) Specifies detection rule(s) to exclude in evaluation (at the inclusion of all other rules). Can be used together with -Include input parameter.

.PARAMETER Summarize

(Optional) Specifies any resultant detection hit(s) be summarized into a single DetectionSummary object for each input JSON document via the Out-EvilSummary function.

.EXAMPLE

PS C:\> "{`"Version`":`"2012-10-17`",`"Statement`":{`"Effect`":`"Allow`",`"Action`":[`"EC2:rUn????ances`",`"iam:P*ole`"],`"Resource`":`"*`"}}" | Find-Evil

Type           : Member
Author         : Official_SkyScalpel_Ruleset
Date           : 7/4/2024 12:00:00AM
ID             : AWSPOLICY_UNICODE_WILDCARDSINGLECHAR_IN_POLICY_ACTION_MATCHING_ONE_ACTION
Name           : Unicode-Encoded Single-Character Wildcard Characters ('?') Present in 
                 String-Format Tokens in Policy Action/NotAction Decoded Path Matching Single 
                 Action ('"EC2:rUn????ances"')
Example        : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:CreateAcce
                 ??Key","Resource":"*"}}
Score          : 250
Depth          : 3
Start          : 64
Content        : "EC2:rUn????ances"
ContentDecoded : "EC2:rUn????ances"

Type           : Member
Author         : Official_SkyScalpel_Ruleset
Date           : 7/4/2024 12:00:00AM
ID             : AWSPOLICY_POLICY_ACTION_MULTIPLE_WILDCARDSINGLECHAR
Name           : String-Format Token in Policy Action/NotAction Decoded Path Contains Multiple 
                 Single-Character Wildcard ('?') Characters ('4')
Example        : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:????teA???
                 ssKey","Resource":"*"}}
Score          : 7.5
Depth          : 3
Start          : 64
Content        : "EC2:rUn????ances"
ContentDecoded : "EC2:rUn????ances"

Type           : Member
Author         : Official_SkyScalpel_Ruleset
Date           : 7/4/2024 12:00:00AM
ID             : AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION
Name           : Unicode-Encoded Wildcard Characters ('*') Present in String-Format Tokens in 
                 Policy Action/NotAction Decoded Path Matching Single Action ('"iam:P*ole"')
Example        : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:CreateAcce
                 *Key","Resource":"*"}}
Score          : 250
Depth          : 3
Start          : 83
Content        : "iam:P*ole"
ContentDecoded : "iam:P*ole"

.EXAMPLE

PS C:\> "{`"Version`":`"2012-10-17`",`"Statement`":{`"Effect`":   `r   `r   `"Allow`",   `n    `"Action`":[`"E\u00432:rUn????an*es`",`"iam:P*ole`"],`"Resource`":`"*`"}}" | Find-Evil -Summarize | Select-Object TotalScore,DetectionCount,UniqueDetectionIDs,JsonDocumentSize,JsonDocument

TotalScore         : 832.5
DetectionCount     : 7
UniqueDetectionIDs : {JSON_WHITESPACE_CARRIAGERETURN, JSON_UNICODE_PRINTABLE_CHARS, 
                     AWSPOLICY_UNICODE_PRINTABLE_CHARS_IN_POLICY_ACTION, 
                     AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION…}
JsonDocumentSize   : 136
JsonDocument       : {"Version":"2012-10-17","Statement":{"Effect":         "Allow",   
                         "Action":["E\u00432:rUn????an*es","iam:P*ole"],"Resource":"*"}}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [SkyScalpel.Detection[]],
        [SkyScalpel.DetectionSummary[]]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String[]]
        $JsonDocument,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ArgumentCompleter(
            {
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Retrieve all DetectionID enum names.
                $detectionIDArr = [System.Array] [SkyScalpel.DetectionID].GetEnumNames()

                # Modify current parameter value (captured at the time the user enters TAB) by appending wildcard
                # character if no wildcard character is found.
                $WordToComplete = $WordToComplete.Contains('*') ? $WordToComplete : "$WordToComplete*"

                # If current parameter substring was single wildcard character then return all DetectionID enum names.
                # Otherwise, filter all DetectionID enum names with current parameter substring.
                ($WordToComplete -ceq '*') ? $detectionIDArr : $detectionIDArr -ilike $WordToComplete
            }
        )]
        [System.String[]]
        $Include = @('*'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ArgumentCompleter(
            {
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Retrieve all DetectionID enum names.
                $detectionIDArr = [System.Array] [SkyScalpel.DetectionID].GetEnumNames()

                # Modify current parameter value (captured at the time the user enters TAB) by appending wildcard
                # character if no wildcard character is found.
                $WordToComplete = $WordToComplete.Contains('*') ? $WordToComplete : "$WordToComplete*"

                # If current parameter substring was single wildcard character then return all DetectionID enum names.
                # Otherwise, filter all DetectionID enum names with current parameter substring.
                ($WordToComplete -ceq '*') ? $detectionIDArr : $detectionIDArr -ilike $WordToComplete
            }
        )]
        [System.String[]]
        $Exclude,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Summarize
    )

    begin
    {
        # Retrieve all DetectionID enum values based on user input -Include and -Exclude parameters.
        $includeDetectionIDArr = $Include.ForEach( { [SkyScalpel.DetectionID].GetEnumValues() -ilike $_ } )
        $excludeDetectionIDArr = $Exclude.ForEach( { [SkyScalpel.DetectionID].GetEnumValues() -ilike $_ } )

        # Set final merged list of DetectionID enum values from user input -Include and -Exclude parameters.
        $detectionIDArr = [SkyScalpel.DetectionID[]] $includeDetectionIDArr.Where( { $_ -inotin $excludeDetectionIDArr } )
    }

    process
    {
        # Iterate over each input JSON document.
        foreach ($curJsonDocument in $JsonDocument)
        {
            # Evaluate detection logic and store potential matching Detection(s) for current JSON document.
            $detectionHitArr = [SkyScalpel.Detection[]] [SkyScalpel.JsonParser]::FindEvil($curJsonDocument,$detectionIDArr)

            # Generate and return DetectionSummary object for current JSON document if user input -Summarize switch parameter is defined.
            # Otherwise return potential matching Detection(s) for current JSON document.
            if ($PSBoundParameters['Summarize'].IsPresent)
            {
                $detectionHitArrSummarized = -not $detectionHitArr ? [SkyScalpel.DetectionSummary]::new($curJsonDocument) : (Out-EvilSummary -Detection $detectionHitArr -JsonDocument $curJsonDocument)
                $detectionHitArrSummarized
            }
            else
            {
                $detectionHitArr
            }
        }
    }

    end
    {

    }
}


function Out-EvilSummary
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Out-EvilSummary
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-EvilSummary consolidates and summarizes all input detection hits generated by Find-Evil function for input JSON document.

.PARAMETER Detection

Specifies Detection object(s) generated by Find-Evil function to consolidate and summarize.

.PARAMETER JsonDocument

Specifies JSON document which produced input Detection object(s) generated by Find-Evil function.

.EXAMPLE

PS C:\> $sf = "{`"Version`":`"2012-10-17`",`"Statement`":{`"Effect`":`"Allow`",`"Action`":[`"EC2:rUn????ances`",`"iam:P*ole`"],`"Resource`":`"*`"}}"
PS C:\> $detectionHits = $sf | Find-Evil
PS C:\> Out-EvilSummary -Detection $detectionHits -JsonDocument $sf | Select-Object TotalScore,DetectionCount,UniqueDetectionIDs,JsonDocumentLength,JsonDocument

TotalScore         : 507.5
DetectionCount     : 3
UniqueDetectionIDs : {AWSPOLICY_UNICODE_WILDCARDSINGLECHAR_IN_POLICY_ACTION_MATCHING_ONE_ACTION
                     , AWSPOLICY_POLICY_ACTION_MULTIPLE_WILDCARDSINGLECHAR, 
                     AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION}
JsonDocumentLength : 
JsonDocument       : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["EC2:rUn??
                     ??ances","iam:P*ole"],"Resource":"*"}}

.EXAMPLE

PS C:\> $sf = "{`"Version`":`"2012-10-17`",`"Statement`":{`"Effect`":   `r   `r   `"Allow`",   `n    `"Action`":[`"E\u00432:rUn????an*es`",`"iam:P*ole`"],`"Resource`":`"*`"}}"
PS C:\> $sf | Find-Evil | Out-EvilSummary -JsonDocument $sf | Select-Object TotalScore,DetectionCount,UniqueDetectionIDs,JsonDocumentLength,JsonDocument

TotalScore         : 832.5
DetectionCount     : 7
UniqueDetectionIDs : {JSON_WHITESPACE_CARRIAGERETURN, JSON_UNICODE_PRINTABLE_CHARS, 
                     AWSPOLICY_UNICODE_PRINTABLE_CHARS_IN_POLICY_ACTION, 
                     AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION…}
JsonDocumentLength : 
JsonDocument       : {"Version":"2012-10-17","Statement":{"Effect":         "Allow",   
                         "Action":["E\u00432:rUn????an*es","iam:P*ole"],"Resource":"*"}}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([SkyScalpel.DetectionSummary])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [SkyScalpel.Detection[]]
        $Detection,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.String]
        $JsonDocument
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $detectionArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $detectionArr before beginning final processing.
        if ($Detection.Count -gt 1)
        {
            # Add all -Detection objects to $detectionArr ArrayList.
            $detectionArr.AddRange($Detection)
        }
        else
        {
            # Add single -Detection object to $detectionArr ArrayList.
            $detectionArr.Add($Detection) | Out-Null
        }
    }

    end
    {
        # Convert user input -Detection parameter ArrayList to Array.
        $detectionArr = [SkyScalpel.Detection[]] $detectionArr.ForEach( { [SkyScalpel.Detection[]] $_ } )

        # Evaluate and return DetectionSummary object for all user input -Detection values.
        [SkyScalpel.JsonParser]::ToEvilSummary($detectionArr,$JsonDocument)
    }
}


function Show-EvilSummary
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-EvilSummary
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-EvilSummary displays multiple pretty-print renderings of input detection summary genereated by Out-EvilSummary function to enable easier visual analysis of detection hit composition and scoring of JSON document.

.PARAMETER DetectionSummary

Specifies DetectionSummary object generated by Out-EvilSummary function to pretty-print.

.PARAMETER SuppressPadding

(Optional) Specifies that leading and trailing padding newline characters not be output.

.EXAMPLE

PS C:\> "{`"Version`":`"2012-10-17`",`"Statement`":{`"Effect`":`"Allow`",`"Action`":[`"EC2:rUn????ances`",`"iam:P*ole`"],`"Resource`":`"*`"}}" | Find-Evil -Summarize | Show-EvilSummary

############################
## Full Detection Details ##
############################

Score          : 250
ID             : AWSPOLICY_UNICODE_WILDCARDSINGLECHAR_IN_POLICY_ACTION_MATCHING_ONE_ACTION
Name           : Unicode-Encoded Single-Character Wildcard Characters (?) Present in String-Format Tokens in Policy Action/NotAction Decoded Path Matching Single Action ("EC2:rUn????ances")
Depth          : 3
Start          : 64
Content        : "EC2:rUn????ances"
ContentDecoded : "EC2:rUn????ances"

Score          : 7.5
ID             : AWSPOLICY_POLICY_ACTION_MULTIPLE_WILDCARDSINGLECHAR
Name           : String-Format Token in Policy Action/NotAction Decoded Path Contains Multiple Single-Character Wildcard (?) Characters (4)
Depth          : 3
Start          : 64
Content        : "EC2:rUn????ances"
ContentDecoded : "EC2:rUn????ances"

Score          : 250
ID             : AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION
Name           : Unicode-Encoded Wildcard Characters (*) Present in String-Format Tokens in Policy Action/NotAction Decoded Path Matching Single Action ("iam:P*ole")
Depth          : 3
Start          : 83
Content        : "iam:P*ole"
ContentDecoded : "iam:P*ole"

################################
## Abridged Detection Details ##
################################

Score                                                                        ID Content
-----                                                                        -- -------
  250 AWSPOLICY_UNICODE_WILDCARDSINGLECHAR_IN_POLICY_ACTION_MATCHING_ONE_ACTION "EC2:rUn????anc…
  7.5                       AWSPOLICY_POLICY_ACTION_MULTIPLE_WILDCARDSINGLECHAR "EC2:rUn????anc…
  250           AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION "iam:P*ole"

#############################
## Detection Summary Stats ##
## (Descending by Score)   ##
#############################

Score Count ID
----- ----- --
  250     1 AWSPOLICY_UNICODE_WILDCARD_IN_POLICY_ACTION_MATCHING_ONE_ACTION
  250     1 AWSPOLICY_UNICODE_WILDCARDSINGLECHAR_IN_POLICY_ACTION_MATCHING_ONE_ACTION
  7.5     1 AWSPOLICY_POLICY_ACTION_MULTIPLE_WILDCARDSINGLECHAR

###################################
## Final Detection Summary Stats ##
###################################

TotalScore             : 507.5
DetectionCount         : 3
UniqueDetectionIDCount : 3

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [SkyScalpel.DetectionSummary]
        $DetectionSummary,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $SuppressPadding
    )

    # Define problematic ANSI escape sequences to remove from strings due to output formatting bug present on pwsh versions prior to 7.3.
    # Simpler fix is the following command, but avoiding making this change since this fix relates to a security issue.
    # E.g. $PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
    $requiresAnsiEscapeSequenceRemoval = [System.Double] (@($PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor) -join '.') -lt 7.3 ? $true : $false
    $ansiEscapeSequenceArr = -not $requiresAnsiEscapeSequenceRemoval ? @() : @(
        ([System.Char] 27 + '[32;1m'),
        ([System.Char] 27 + '[0m')
    )

    # Output leading padding unless user input -SuppressPadding switch parameter is defined.
    if (-not $PSBoundParameters['SuppressPadding'].IsDefined)
    {
        Write-Host ''
    }

    ############################
    ## Full Detection Details ##
    ############################

    # Pretty-print full Detection details.
    Write-Host "############################`n## Full Detection Details ##`n############################`n" -ForegroundColor Cyan

    # Convert full Detection details to string and split on newlines, handling removal of potential ANSI escape sequences.
    $fullDetectionDetailsStr = $DetectionSummary.Detections | Select-Object Score,ID,Name,Depth,Start,Content,ContentDecoded | Out-String
    if ($requiresAnsiEscapeSequenceRemoval)
    {
        # Remove each ANSI escape sequence from full Detection details string output.
        foreach ($ansiEscapeSequence in $ansiEscapeSequenceArr)
        {
            $fullDetectionDetailsStr = $fullDetectionDetailsStr.Replace($ansiEscapeSequence,'')
        }
    }
    $fullDetectionDetailsStrSplit = $fullDetectionDetailsStr.Trim().Split("`n")

    # Pretty-print each line of full Detection details, highlighting text in specific rows.
    foreach ($line in $fullDetectionDetailsStrSplit)
    {
        # If line does not contain a property then print line and continue.
        if (-not $line.Contains(' : '))
        {
            Write-Host $line
            continue
        }

        # Calculate property and value portion of current line along with separately extracting property name.
        $propLen = $line.IndexOf(' : ') + 3
        $propName = $line.Substring(0,$line.IndexOf(' '))
        $linePropSubstr = $line.Substring(0,$propLen)
        $lineValSubstr = $line.Substring($propLen)

        # Print property line as standard Green to mimic PowerShell object output.
        Write-Host $linePropSubstr -NoNewline -ForegroundColor Green

        # Print value with color-coding where applicable based on property name.
        switch($propName)
        {
            'Score'          { Write-Host $lineValSubstr -ForegroundColor Red      }
            'ID'             { Write-Host $lineValSubstr -ForegroundColor Yellow   }
            'Depth'          { Write-Host $lineValSubstr -ForegroundColor Gray     }
            'Start'          { Write-Host $lineValSubstr -ForegroundColor Gray     }
            'Content'        { Write-Host $lineValSubstr -ForegroundColor DarkGray }
            'ContentDecoded' { Write-Host $lineValSubstr -ForegroundColor DarkGray }
            'Name' {
                # Output lines while highlighting any strings encapsulated by single quotes to emphasize custom values.
                $highlight = $false
                $lineValSubstr.Split("'").ForEach(
                {
                    if ($highlight)
                    {
                        Write-Host $_ -NoNewline -ForegroundColor Magenta
                        $highlight = $false
                    }
                    else
                    {
                        Write-Host $_ -NoNewline -ForegroundColor Cyan
                        $highlight = $true
                    }
                } )
                Write-Host ''
            }
            default { Write-Host $lineValSubstr }
        }
    }
    Write-Host ''

    ################################
    ## Abridged Detection Details ##
    ################################

    # Pretty-print abridged Detection details.
    Write-Host "################################`n## Abridged Detection Details ##`n################################`n" -ForegroundColor Cyan

    # Convert Detections to string and split on newlines, handling removal of potential ANSI escape sequences.
    $abridgedDetectionDetailsStr = $DetectionSummary.Detections | Select-Object Score,ID,Content | Out-String
    if ($requiresAnsiEscapeSequenceRemoval)
    {
        # Remove each ANSI escape sequence from Detections string output.
        foreach ($ansiEscapeSequence in $ansiEscapeSequenceArr)
        {
            $abridgedDetectionDetailsStr = $abridgedDetectionDetailsStr.Replace($ansiEscapeSequence,'')
        }
    }
    $abridgedDetectionDetailsStrSplit = $abridgedDetectionDetailsStr.Split("`n").Where( { $_ -and $_.TrimStart("`r") } )

    # Calculate lengths for each property in header.
    $headerPropLine = $abridgedDetectionDetailsStrSplit[0]
    $propLenObj = [PSCustomObject] @{ }
    foreach ($headerSubstr in ($headerPropLine -csplit '(\s*[^\s]+\s?)').Where( { $_ } ))
    {
        Add-Member -InputObject $propLenObj -MemberType NoteProperty -Name $headerSubstr.Trim() -Value $headerSubstr.Length
    }

    # Print leading two property lines as standard Green to mimic PowerShell object output.
    $propLineCount = 2
    Write-Host (($abridgedDetectionDetailsStrSplit | Select-Object -First $propLineCount) -join "`n") -ForegroundColor Green

    # Pretty-print remaining non-property lines, highlighting text in specific columns.
    foreach ($line in ($abridgedDetectionDetailsStrSplit | Select-Object -Skip $propLineCount))
    {
        # Parse lines by column based on previously parsed property lengths in header, respecting ordering of headers.
        $lineObj = [PSCustomObject] @{}
        $startIndex = 0
        $propNameArrOrdered = $propLenObj.PSObject.Properties.Where( { $_.MemberType -eq 'NoteProperty' } ).Name
        foreach ($propName in $propNameArrOrdered)
        {
            # Extract current line substring for current property,handling if last property (ignoring substring length in that case).
            $propLength = $propLenObj.$propName
            $lineValSubstr = $propName -ceq $propNameArrOrdered[-1] ? $line.Substring($startIndex) : $line.Substring($startIndex,$propLength)
            $startIndex += $propLength

            # Print value with color-coding where applicable based on property name.
            switch($propName)
            {
                'Score'   { Write-Host $lineValSubstr -NoNewline -ForegroundColor Red      }
                'ID'      { Write-Host $lineValSubstr -NoNewline -ForegroundColor Yellow   }
                'Content' { Write-Host $lineValSubstr -NoNewline -ForegroundColor DarkGray }
                default   { Write-Host $lineValSubstr }
            }
        }
        Write-Host ''
    }
    Write-Host ''

    #############################
    ## Detection Summary Stats ##
    #############################

    # Pretty-print Detection summary stats.
    Write-Host "#############################`n## Detection Summary Stats ##`n## (Descending by Score)   ##`n#############################`n" -ForegroundColor Cyan

    # Convert Detection summary stats to string and split on newlines, handling removal of potential ANSI escape sequences.
    $detectionSummaryStatsStr = $DetectionSummary.Detections | Select-Object Score,ID | Group-Object ID | Select-Object @{ name = 'Score'; expression = {($_.Group.Score | Measure-Object -Sum).Sum} },Count,@{ name = 'ID'; expression = {$_.Name} } | Sort-Object Score -Descending | Out-String
    if ($requiresAnsiEscapeSequenceRemoval)
    {
        # Remove each ANSI escape sequence from Detection summary stats string output.
        foreach ($ansiEscapeSequence in $ansiEscapeSequenceArr)
        {
            $detectionSummaryStatsStr = $detectionSummaryStatsStr.Replace($ansiEscapeSequence,'')
        }
    }
    $detectionSummaryStatsStrSplit = $detectionSummaryStatsStr.Split("`n").Where( { $_ -and $_.TrimStart("`r") } )

    # Calculate lengths for each property in header.
    $headerPropLine = $detectionSummaryStatsStrSplit[0]
    $propLenObj = [PSCustomObject] @{ }
    foreach ($headerSubstr in ($headerPropLine -csplit '(\s*[^\s]+\s?)').Where( { $_ } ))
    {
        Add-Member -InputObject $propLenObj -MemberType NoteProperty -Name $headerSubstr.Trim() -Value $headerSubstr.Length
    }

    # Print leading two property lines as standard Green to mimic PowerShell object output.
    $propLineCount = 2
    Write-Host (($detectionSummaryStatsStrSplit | Select-Object -First $propLineCount) -join "`n") -ForegroundColor Green

    # Pretty-print remaining non-property lines, highlighting text in specific columns.
    foreach ($line in ($detectionSummaryStatsStrSplit | Select-Object -Skip $propLineCount))
    {
        # Parse lines by column based on previously parsed property lengths in header, respecting ordering of headers.
        $lineObj = [PSCustomObject] @{}
        $startIndex = 0
        $propNameArrOrdered = $propLenObj.PSObject.Properties.Where( { $_.MemberType -eq 'NoteProperty' } ).Name
        foreach ($propName in $propNameArrOrdered)
        {
            # Extract current line substring for current property,handling if last property (ignoring substring length in that case).
            $propLength = $propLenObj.$propName
            $lineValSubstr = $propName -ceq $propNameArrOrdered[-1] ? $line.Substring($startIndex) : $line.Substring($startIndex,$propLength)
            $startIndex += $propLength

            # Print value with color-coding where applicable based on property name.
            switch($propName)
            {
                'Score' { Write-Host $lineValSubstr -NoNewline -ForegroundColor Red    }
                'Count' { Write-Host $lineValSubstr -NoNewline -ForegroundColor Gray   }
                'ID'    { Write-Host $lineValSubstr -NoNewline -ForegroundColor Yellow }
                default { Write-Host $lineValSubstr }
            }
        }
        Write-Host ''
    }
    Write-Host ''

    ###################################
    ## Final Detection Summary Stats ##
    ###################################

    # Pretty-print Detection summary stats.
    Write-Host "###################################`n## Final Detection Summary Stats ##`n###################################`n" -ForegroundColor Cyan

    # Print as if a PowerShell object output but in horizontal view (not Format-Table)
    # even though it is too small to normally output in this format by PowerShell.
    Write-Host 'TotalScore             : '   -NoNewline -ForegroundColor Green
    Write-Host $DetectionSummary.TotalScore             -ForegroundColor Red
    Write-Host 'DetectionCount         : '   -NoNewline -ForegroundColor Green
    Write-Host $DetectionSummary.DetectionCount         -ForegroundColor Gray
    Write-Host 'UniqueDetectionIDCount : '   -NoNewline -ForegroundColor Green
    Write-Host $DetectionSummary.UniqueDetectionIDCount -ForegroundColor Gray

    # Outut trailing padding unless user input -SuppressPadding switch parameter is defined.
    if (-not $PSBoundParameters['SuppressPadding'].IsDefined)
    {
        Write-Host ''
    }
}