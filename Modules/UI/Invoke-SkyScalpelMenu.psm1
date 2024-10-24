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



##########################################################################################################
## All functions in this module are solely for the menu-driven Invoke-SkyScalpel exploratory experience ##
## and do not provide any additional obfuscation, deobfuscation or detection functionality.             ##
## This menu-driven experience is included to more easily enable Red and Blue Teamers to explore the    ##
## SkyScalpel options in a quick and visual manner.                                                     ##
##########################################################################################################



# Get location of this script no matter what the current directory is for the process executing this script.
$scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 

function Invoke-SkyScalpel
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Invoke-SkyScalpel
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: New-ObfuscationContainer, Split-Command, Show-AsciiArt, Show-HelpMenu, Show-Menu
Optional Dependencies: None

.DESCRIPTION

Invoke-SkyScalpel orchestrates the application of all obfuscation, deobfuscation and detection functions to input JSON document in a colorful and visually-pleasing format to demonstrate the effectiveness of layered obfuscation techniques and corresponding detection logic.

.PARAMETER JsonDocument

Specifies initial JSON document to obfuscate, deobfuscate and/or detect.

.PARAMETER JsonDocumentPath

Specifies path to initial JSON document to obfuscate, deobfuscate and/or detect (can be local file, UNC-path, or remote URI).

.PARAMETER Command

(Optional) Specifies obfuscation, deobfuscation and/or detection command(s) to run against input -JsonDocument or -JsonDocumentPath parameter.

.PARAMETER OutputFormat

(Optional - only works if -Command is specified and -NoExit is not specified) Specifies output format of final obfuscated JSON document, with 'string' returning JSON document as string and 'container' returning entire obfuscation container object (which includes all layers of obfuscation).

.PARAMETER NoExit

(Optional) Specifies that the function not exit after running obfuscation, deobfuscation and/or detection commands defined in -Command parameter.

.PARAMETER Quiet

(Optional) Specifies that the function suppress unnecessary output during startup (and during duration of function calls if -Command is specified).

.EXAMPLE

C:\PS> Invoke-SkyScalpel

.EXAMPLE

C:\PS> Invoke-SkyScalpel -JsonDocument '{"country":"Kosovë","city":"Gjakova"}'

.EXAMPLE

C:\PS> Invoke-SkyScalpel -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}' -Command 'OBFUSCATE\JSON\UNICODE\4' -Quiet -NoExit

.EXAMPLE

C:\PS> Invoke-SkyScalpel -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}' -Command 'OBFUSCATE,****,****' -Quiet

{     "Ver\u0073\u0069\u006fn"        :             "\u0032\u0030\u0031\u0032-10-\u00317"            ,     "St\u0061te\u006de\u006E\u0074"          :  {  "E\u0066\u0066ect"   :  "\u0041ll\u006f\u0077"      ,   "\u0041\u0063\u0074i\u006fn"    :   [    "\u0065c2:R??I\u004E\u003Ft?\u004e??\u003F"   ,         "\u0069AM\u003ap\u0061??r\u004Fl\u0065"     ]   ,  "R\u0065s\u006F\u0075r\u0063\u0065" :   "*"        } }

.EXAMPLE

C:\PS> Invoke-SkyScalpel -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}' -Command 'OBFUSCATE\JSON\UNICODE\3,OBFUSCATE\JSON\WHITESPACE\*' -OutputFormat container -Quiet

Layer                         : 2
JsonDocument                  : {"\u0056e\u0072s\u0069o\u006E"   :"2\u0030\u0031\u0032\u002D\u00310\u002d\u00317", 
                                 "S\u0074\u0061\u0074em\u0065\u006Et"   :{"E\u0066f\u0065c\u0074": "\u0041llow" ,  
                                "Action"  :  ["\u0065\u00632\u003aRu\u006E\u0049n\u0073\u0074\u0061\u006Eces"   ,  
                                 "i\u0061m\u003A\u0050\u0061\u0073\u0073R\u006F\u006Ce"   ]  ,   "Resource"   :  
                                "*" } }  
JsonDocumentTokenized         : {Depth: 0, Length: 1, Format: , Type: BeginObject, SubType: , Content: {, 
                                ContentDecoded: {, Path.ContentDecoded: , Path.Content: , Depth: 1, Length: 29, 
                                Format: String, Type: Name, SubType: ObjectMember, Content: 
                                "\u0056e\u0072s\u0069o\u006E", ContentDecoded: "Version", Path.ContentDecoded: 
                                Version, Path.Content: \u0056e\u0072s\u0069o\u006E, Depth: 1, Length: 3, Format: , 
                                Type: Whitespace, SubType: , Content:    , ContentDecoded:    , 
                                Path.ContentDecoded: Version, Path.Content: \u0056e\u0072s\u0069o\u006E, Depth: 1, 
                                Length: 1, Format: , Type: NameSeparator, SubType: , Content: :, ContentDecoded: 
                                :, Path.ContentDecoded: Version, Path.Content: \u0056e\u0072s\u0069o\u006E…}
JsonDocumentSize              : 339
JsonDocumentTokenizedSize     : 43
JsonDocumentValueCount        : 5
JsonDocumentDepth             : 4
JsonDocumentMD5               : D50D77D3B3DA76AF7766EF2986C12417
JsonDocumentOrig              : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances",
                                "iam:PassRole"],"Resource":"*"}}
JsonDocumentOrigSize          : 115
JsonDocumentOrigTokenizedSize : 25
JsonDocumentOrigCount         : 5
JsonDocumentOrigDepth         : 4
JsonDocumentOrigMD5           : ADD41BA60AF2AC95660F994280445566
JsonDocumentPath              : N/A
History                       : {@{Layer=0; JsonDocument={"Version":"2012-10-17","Statement":{"Effect":"Allow","Act
                                ion":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}; 
                                JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; JsonDocumentSize=115; 
                                JsonDocumentTokenizedSize=25; JsonDocumentValueCount=5; JsonDocumentDepth=4; 
                                JsonDocumentMD5=ADD41BA60AF2AC95660F994280445566; JsonDocumentOrig={"Version":"2012
                                -10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],
                                "Resource":"*"}}; JsonDocumentOrigSize=115; JsonDocumentOrigTokenizedSize=25; 
                                JsonDocumentOrigCount=5; JsonDocumentOrigDepth=4; 
                                JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; 
                                Function=New-ObfuscationContainer; CommandLineSyntax='{"Version":"2012-10-17","Stat
                                ement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*
                                "}}'; CliSyntax=System.Object[]}, @{Layer=1; JsonDocument={"\u0056e\u0072s\u0069o\u
                                006E":"2\u0030\u0031\u0032\u002D\u00310\u002d\u00317","S\u0074\u0061\u0074em\u0065\
                                u006Et":{"E\u0066f\u0065c\u0074":"\u0041llow","Action":["\u0065\u00632\u003aRu\u006
                                E\u0049n\u0073\u0074\u0061\u006Eces","i\u0061m\u003A\u0050\u0061\u0073\u0073R\u006F
                                \u006Ce"],"Resource":"*"}}; JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; 
                                JsonDocumentSize=300; JsonDocumentTokenizedSize=25; JsonDocumentValueCount=5; 
                                JsonDocumentDepth=4; JsonDocumentMD5=0E50E82AB6851D807F16B7E28343A8F0; JsonDocument
                                Orig={"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstan
                                ces","iam:PassRole"],"Resource":"*"}}; JsonDocumentOrigSize=115; 
                                JsonDocumentOrigTokenizedSize=25; JsonDocumentOrigCount=5; 
                                JsonDocumentOrigDepth=4; JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; 
                                Function=Add-RandomUnicode; CliSyntax=System.Object[]; 
                                CommandLineSyntax=Add-RandomUnicode -RandomNodePercent 75 -RandomCharPercent 40}, 
                                @{Layer=2; JsonDocument={"\u0056e\u0072s\u0069o\u006E"   
                                :"2\u0030\u0031\u0032\u002D\u00310\u002d\u00317",  
                                "S\u0074\u0061\u0074em\u0065\u006Et"   :{"E\u0066f\u0065c\u0074": "\u0041llow" ,  
                                "Action"  :  ["\u0065\u00632\u003aRu\u006E\u0049n\u0073\u0074\u0061\u006Eces"   ,  
                                 "i\u0061m\u003A\u0050\u0061\u0073\u0073R\u006F\u006Ce"   ]  ,   "Resource"   :  
                                "*" } }  ; JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; 
                                JsonDocumentSize=339; JsonDocumentTokenizedSize=43; JsonDocumentValueCount=5; 
                                JsonDocumentDepth=4; JsonDocumentMD5=D50D77D3B3DA76AF7766EF2986C12417; JsonDocument
                                Orig={"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstan
                                ces","iam:PassRole"],"Resource":"*"}}; JsonDocumentOrigSize=115; 
                                JsonDocumentOrigTokenizedSize=25; JsonDocumentOrigCount=5; 
                                JsonDocumentOrigDepth=4; JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; 
                                Function=Add-RandomWhitespace; CliSyntax=System.Object[]; 
                                CommandLineSyntax=Add-RandomWhitespace -RandomNodePercent 50 -RandomLength 
                                @(1..3)}}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'JsonDocument')]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'JsonDocument')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $JsonDocument,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'JsonDocumentPath')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $JsonDocumentPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('string','container')]
        [System.String]
        $OutputFormat = 'string',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $NoExit,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
    )

    # If both -JsonDocument and -JsonDocumentPath input parameters are defined then throw warning message and proceed with only using -JsonDocument.
    if ($PSBoundParameters['JsonDocument'] -and $PSBoundParameters['JsonDocumentPath'])
    {
        Write-Warning 'Both -JsonDocument and -JsonDocumentPath input parameters are defined. Defaulting to -JsonDocument input parameter.'
    }

    # Store input -JsonDocument or -JsonDocumentPath input parameters as CLI commands for automated processing.
    if ($PSBoundParameters['JsonDocument'])
    {
        # Build new obfuscation container.
        $jsonObfContainer = New-ObfuscationContainer -JsonDocument $JsonDocument

        # Set N/A value in JsonDocumentPath property of newly-created obfuscation container.
        $jsonObfContainer.JsonDocumentPath = 'N/A'
    }
    elseif ($PSBoundParameters['JsonDocumentPath'])
    {
        # Read in $JsonDocument value from -JsonDocumentPath (either file on disk or remotely hosted file).
        if ((Test-Path $JsonDocumentPath) -or ($userInputOptionValue -match '^(http|https):[/\\]'))
        {
            # Check if -JsonDocumentPath input parameter is a URL or a directory.
            if ($JsonDocumentPath -match '^(http|https):[/\\]')
            {
                # JsonDocumentPath is a URL.

                # Download content from remote location and set to $JsonDocument variable (overwriting existing value if present).
                $JsonDocument = (New-Object Net.WebClient).DownloadString($JsonDocumentPath)

                # Build new obfuscation container.
                $jsonObfContainer = New-ObfuscationContainer -JsonDocument $JsonDocument

                # Set user-input JSONDOCUMENTPATH value into JsonDocumentPath property of newly-created obfuscation container.
                $jsonObfContainer.JsonDocumentPath = $JsonDocumentPath
            }
            elseif ((Get-Item $JsonDocumentPath) -is [System.IO.DirectoryInfo])
            {
                # JsonDocumentPath is a directory instead of a file.
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' -JsonDocumentPath path is a directory instead of a file (' -NoNewline
                Write-Host $JsonDocumentPath -NoNewline -ForegroundColor Cyan
                Write-Host ").`n" -NoNewline
            }
            else
            {
                # Build new obfuscation container with file content from user-input -JsonDocumentPath parameter.
                $jsonObfContainer = New-ObfuscationContainer -JsonDocumentPath (Resolve-Path $JsonDocumentPath).Path

                # Set user-input JSONDOCUMENTPATH value into JsonDocumentPath property of newly-created obfuscation container.
                $jsonObfContainer.JsonDocumentPath = (Resolve-Path $JsonDocumentPath).Path
            }
        }
        else
        {
            # JsonDocumentPath not found (failed Test-Path).
            Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
            Write-Host ' -JsonDocumentPath path not found (' -NoNewline
            Write-Host $JsonDocumentPath -NoNewline -ForegroundColor Cyan
            Write-Host ").`n" -NoNewline
        }
    }
    else
    {
        # Build new obfuscation container with "empty" command (passed as single whitespace to avoid null argument error from New-ObfuscationContainer).
        $jsonObfContainer = New-ObfuscationContainer -JsonDocument ' '
    }

    # Append Command to CliCommands if specified by user input.
    if ($PSBoundParameters['Command'])
    {
        # Extract potential concatenated commands while applying special logic if 'set jsondocument' command is present to avoid setting an incomplete value.

        # Split -Command value into appropriate sub-commands if applicable.
        $cliCommand = $Command | Split-Command

        # If -Quiet input parameter is defined, create empty Write-Host and Start-Sleep proxy functions to cause any Write-Host or Start-Sleep invocations to do nothing until non-interactive -Command values are finished being processed.
        if ($PSBoundParameters['Quiet'].IsPresent)
        {
            function global:Write-Host {}
            function global:Start-Sleep {}
        }
    }

    # Define options menu to be displayed when 'SHOW OPTIONS' command is entered.
    $optionMenu = @(
        [PSCustomObject] @{ Name = 'JsonDocumentPath'      ; Value = $JsonDocumentPath; Settable = $true  }
        [PSCustomObject] @{ Name = 'JsonDocument'          ; Value = $JsonDocument    ; Settable = $true  }
        [PSCustomObject] @{ Name = 'CommandLineSyntax'     ; Value = @()              ; Settable = $false }
        [PSCustomObject] @{ Name = 'ExecutionCommands'     ; Value = @()              ; Settable = $false }
        [PSCustomObject] @{ Name = 'ObfuscatedJsonDocument'; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'Length'                ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'Depth'                 ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'DetectionScore'        ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'DetectionCount'        ; Value = $null            ; Settable = $false }
    )

    # Ensure SkyScalpel module was properly imported before continuing.
    if (-not (Get-Module -Name SkyScalpel).Where( { $_.ModuleType -eq 'Script' } ) )
    {
        # Set path to .psd1 file and encapsulate with quotes if the path contains whitespace for more accurate output to user.
        $psd1Path = Join-Path -Path ($scriptDir -ireplace '/Modules/UI$','') -ChildPath 'SkyScalpel.psd1'
        if ($psd1Path.Contains(' '))
        {
            $psd1Path = "`"$psd1Path`""
        }

        # Output error message and exit if SkyScalpel module is not loaded.
        Write-Host "`n`nERROR: SkyScalpel module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $psd1Path`n`n" -ForegroundColor Yellow
        Start-Sleep -Seconds 5

        exit
    }

    # Build interactive menus.
    $lineHeader = '[*] '

    # Main Menu.
    $menuLevel = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'OBFUSCATE   '; Description = '<Obfuscate> JSON Document'   }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'DEOBFUSCATE '; Description = '<Deobfuscate> JSON Document' }
    )

    # Main\Obfuscate Menu.
    $menuLevel_Obfuscate = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'JSON     '; Description = '<Obfuscate> JSON Document with generic JSON obfuscation'        }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'AWSPOLICY'; Description = '<Obfuscate> JSON Document with AWS Policy-specific obfuscation' }
    )

    # Main\Obfuscate\JSON Menu.
    $menuLevel_Obfuscate_JSON = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WHITESPACE'; Description = 'Randomly insert <Whitespace> tokens'                       }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'UNICODE   '; Description = 'Randomly substitute <Unicode> encoding in eligible tokens' }
    )

    # Main\Obfuscate\AWSPolicy Menu.
    $menuLevel_Obfuscate_AWSPolicy = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WILDCARD          '; Description = 'Randomly insert <Wildcard> characters into eligible tokens'                  }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WILDCARDSINGLECHAR'; Description = 'Randomly insert <Single-Character Wildcard> characters into eligible tokens' }
    )

    # Main\Deobfuscate Menu.
    $menuLevel_Deobfuscate = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'JSON     '; Description = '<Deobfuscate> JSON Document''s generic JSON obfuscation'        }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'AWSPOLICY'; Description = '<Deobfuscate> JSON Document''s AWS Policy-specific obfuscation' }
    )

    # Main\Deobfuscate\JSON Menu.
    $menuLevel_Deobfuscate_JSON = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WHITESPACE'; Description = 'Randomly remove <Whitespace> tokens'                       }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'UNICODE   '; Description = 'Randomly substitute <Unicode> encoding in eligible tokens' }
    )

    # Main\Deobfuscate\AWSPolicy Menu.
    $menuLevel_Deobfuscate_AWSPolicy = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WILDCARD          '; Description = 'Randomly remove <Wildcard> characters from eligible Action/NotAction tokens' }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WILDCARDSINGLECHAR'; Description = 'Randomly remove <Single-Character Wildcard> characters from eligible Action/NotAction tokens' }
    )

    # Define arguments required by all obfuscation functions to properly track modification(s) and return result as appropriately formatted JsonTokenEnriched[] for UI highlighting purposes.
    # These arguments will be executed but not included in CommandLineSyntax property tracking or UI since they are only used when invoking functions from current Invoke-SkyScalpel UI function.
    $requiredFunctionPrefixArgumentsToHideFromUI = '$jsonDocument | '
    $requiredFunctionSuffixArgumentsToHideFromUI = ' -Target JsonTokenEnriched -TrackModification'

    # Main\Obfuscate\JSON\Whitespace Menu.
    $descriptionPrefix = $menuLevel_Obfuscate_JSON.Where( { $_.Option.TrimEnd() -ceq 'WHITESPACE' } )[0].Description
    $menuLevel_Obfuscate_JSON_Whitespace = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWhitespace -RandomNodePercent 25 -RandomLength @(1..2)'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWhitespace -RandomNodePercent 50 -RandomLength @(1..3)'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWhitespace -RandomNodePercent 75 -RandomLength @(1..4)'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWhitespace -RandomNodePercent 100 -RandomLength @(1..5)' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Obfuscate\JSON\Unicode Menu.
    $descriptionPrefix = $menuLevel_Obfuscate_JSON.Where( { $_.Option.TrimEnd() -ceq 'UNICODE' } )[0].Description
    $menuLevel_Obfuscate_JSON_Unicode = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomUnicode -RandomNodePercent 25 -RandomCharPercent 10'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomUnicode -RandomNodePercent 50 -RandomCharPercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomUnicode -RandomNodePercent 75 -RandomCharPercent 40'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 50' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Obfuscate\AWSPolicy\Wildcard Menu.
    $descriptionPrefix = $menuLevel_Obfuscate_AWSPolicy.Where( { $_.Option.TrimEnd() -ceq 'WILDCARD' } )[0].Description
    $menuLevel_Obfuscate_AWSPolicy_Wildcard = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcard -RandomNodePercent 25 -RandomCharPercent 10 -RandomLength 1 -Format Plaintext'               + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcard -RandomNodePercent 50 -RandomCharPercent 25 -RandomLength @(1,2) -Format Matching'           + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcard -RandomNodePercent 75 -RandomCharPercent 40 -RandomLength @(1,2) -Format Matching'           + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 50 -RandomLength @(1,2) -Format Plaintext,Unicode' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Obfuscate\AWSPolicy\WildcardSingleChar Menu.
    $descriptionPrefix = $menuLevel_Obfuscate_AWSPolicy.Where( { $_.Option.TrimEnd() -ceq 'WILDCARDSINGLECHAR' } )[0].Description
    $menuLevel_Obfuscate_AWSPolicy_WildcardSingleChar = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcardSingleChar -RandomNodePercent 25 -RandomCharPercent 10 -Format Plaintext'          + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcardSingleChar -RandomNodePercent 50 -RandomCharPercent 25 -Format Matching'           + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcardSingleChar -RandomNodePercent 75 -RandomCharPercent 40 -Format Matching'           + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 50 -Format Plaintext,Unicode' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\JSON\Whitespace.
    $descriptionPrefix = $menuLevel_Deobfuscate_JSON.Where( { $_.Option.TrimEnd() -ceq 'WHITESPACE' } )[0].Description
    $menuLevel_Deobfuscate_JSON_Whitespace = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\JSON\Unicode.
    $descriptionPrefix = $menuLevel_Deobfuscate_JSON.Where( { $_.Option.TrimEnd() -ceq 'UNICODE' } )[0].Description
    $menuLevel_Deobfuscate_JSON_Unicode = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomUnicode -RandomNodePercent 25 -RandomCharPercent 25'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomUnicode -RandomNodePercent 50 -RandomCharPercent 50'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomUnicode -RandomNodePercent 75 -RandomCharPercent 75'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\AWSPolicy\Wildcard.
    $descriptionPrefix = $menuLevel_Deobfuscate_AWSPolicy.Where( { $_.Option.TrimEnd() -ceq 'WILDCARD' } )[0].Description
    $menuLevel_Deobfuscate_AWSPolicy_Wildcard = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 25 -RandomCharPercent 25 -RandomLength @(1,2)'               + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 50 -RandomCharPercent 50 -RandomLength @(2,3,4)'             + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 75 -RandomCharPercent 75 -RandomLength @(5,6,7)'             + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 25 -Type Substring' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\AWSPolicy\WildcardSingleChar.
    $descriptionPrefix = $menuLevel_Deobfuscate_AWSPolicy.Where( { $_.Option.TrimEnd() -ceq 'WILDCARDSINGLECHAR' } )[0].Description
    $menuLevel_Deobfuscate_AWSPolicy_WildcardSingleChar = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1 '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcardSingleChar -RandomNodePercent 25 -RandomCharPercent 25'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2 '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcardSingleChar -RandomNodePercent 50 -RandomCharPercent 50'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3 '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcardSingleChar -RandomNodePercent 75 -RandomCharPercent 75'   + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4 '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Input options to display non-interactive menus or to perform actions.
    $allInputOptionMenu = [PSCustomObject] @{
        Tutorial         = [PSCustomObject] @{ Option = @('tutorial')                            ; Description = '<Tutorial> of how to use this tool                 ' }
        ShowHelp         = [PSCustomObject] @{ Option = @('help','get-help','?','-?','/?','menu'); Description = 'Show this <Help> Menu                              ' }
        ShowOption       = [PSCustomObject] @{ Option = @('show options','show','options')       ; Description = '<Show options> for payload to obfuscate            ' }
        ClearScreen      = [PSCustomObject] @{ Option = @('clear','clear-host','cls')            ; Description = '<Clear> screen                                     ' }
        CopyToClipboard  = [PSCustomObject] @{ Option = @('copy','clip','clipboard')             ; Description = '<Copy> ObfuscatedJsonDocument to clipboard         ' }
        OutputTree       = [PSCustomObject] @{ Option = @('tree')                                ; Description = 'Print <Tree> format of ObfuscatedJsonDocument      ' }
        OutputToDisk     = [PSCustomObject] @{ Option = @('out')                                 ; Description = 'Write ObfuscatedJsonDocument <Out> to disk         ' }
        ExportToDisk     = [PSCustomObject] @{ Option = @('export')                              ; Description = '<Export> $jsonObfContainer CliXml to disk          ' }
        FindEvil         = [PSCustomObject] @{ Option = @('detect','find-evil')                  ; Description = '<Detect> obfuscation in ObfuscatedJsonDocument     ' }
        ResetObfuscation = [PSCustomObject] @{ Option = @('reset')                               ; Description = '<Reset> ALL obfuscation for ObfuscatedJsonDocument ' }
        UndoObfuscation  = [PSCustomObject] @{ Option = @('undo')                                ; Description = '<Undo> LAST obfuscation for ObfuscatedJsonDocument ' }
        BackMenu         = [PSCustomObject] @{ Option = @('back','cd ..')                        ; Description = 'Go <Back> to previous obfuscation menu             ' }
        Exit             = [PSCustomObject] @{ Option = @('quit','exit')                         ; Description = '<Quit> Invoke-SkyScalpel                           ' }
        HomeMenu         = [PSCustomObject] @{ Option = @('home','main')                         ; Description = 'Return to <Home> Menu                              ' }
    }

    # Display animated ASCII art and banner if -Quiet in parameter is not specified.
    if (-not $PSBoundParameters['Quiet'].IsPresent)
    {
        # Obligatory ASCII Art.
        Show-AsciiArt -Animated
        Start-Sleep -Seconds 1

        # Show Help Menu once at beginning of script.
        Show-HelpMenu -InputOptionMenu $allInputOptionMenu
    }

    # Main loop for user interaction. Show-Menu function displays current function along with acceptable input options (defined in arrays instantiated above).
    # User input and validation is handled within Show-Menu.
    $userResponse = ''
    while ($allInputOptionMenu.Exit.Option -inotcontains ([System.String] $userResponse))
    {
        $userResponse = ([System.String] $userResponse).Trim()

        if ($allInputOptionMenu.HomeMenu.Option -icontains ([System.String] $userResponse))
        {
            $userResponse = ''
        }

        # Display menu if it is defined in a menu variable with $userResponse in the variable name.
        $menuVariable = (Get-Variable -Name "MenuLevel$userResponse" -ErrorAction SilentlyContinue).Value
        if (-not $menuVariable)
        {
            Write-Error "The variable MenuLevel$userResponse does not exist."

            $userResponse = 'quit'
        }
        else {
            $menuResponse = Show-Menu -Menu $menuVariable -MenuName $userResponse -OptionMenu $optionMenu -InputOptionMenu $allInputOptionMenu -JsonObfContainer $jsonObfContainer -CliCommand:$cliCommand

            # Parse out next menu response from user and JsonObfContainer and potential remaining CliCommand returned from Show-Menu function above.
            $userResponse     = [System.String]   $menuResponse.UserResponse.ToLower()
            $jsonObfContainer = [PSCustomObject]  $menuResponse.JsonObfContainer
            $cliCommand       = [System.String[]] $menuResponse.CliCommand
        }

        if (($userResponse -eq 'quit') -and $PSBoundParameters['Command'] -and -not $PSBoundParameters['NoExit'].IsPresent)
        {
            # Return current obfuscated command as a string or return the entire command container based on -OutputFormat input parameter value.
            switch ($OutputFormat)
            {
                'string' {
                    return $jsonObfContainer.JsonDocument.Trim("`n")
                }
                'container' {
                    return $jsonObfContainer
                }
                default
                {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }
        }
    }
}


function Show-Menu
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-Menu
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Split-Command, New-ObfuscationContainer, Add-ObfuscationLayer, Out-JsonObject, Show-HelpMenu, Show-OptionsMenu, Show-Tutorial, Find-Evil, Show-EvilSummary, Remove-ObfuscationLayer
Optional Dependencies: None

.DESCRIPTION

Show-Menu displays current menu with obfuscation navigation and application options for Invoke-SkyScalpel and handles interactive user input loop.

.PARAMETER Menu

Specifies menu options to display, with acceptable input options parsed out of this array.

.PARAMETER MenuName

(Optional) Specifies menu header display and breadcrumb used in the interactive prompt display.

.PARAMETER OptionMenu

Specifies properties and values to be displayed when 'SHOW OPTIONS' command is entered.

.PARAMETER InputOptionMenu

Specifies all acceptable input options in addition to each menu's specific acceptable inputs (e.g. 'EXIT', 'QUIT', 'BACK', 'HOME', 'MAIN', etc.).

.PARAMETER CliCommand

(Optional) Specifies user input commands during non-interactive CLI usage.

.PARAMETER JsonObfContainer

Specifies obfuscation container from which relevant values will be extracted or modified if needed.

.EXAMPLE

C:\PS> Show-Menu

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $Menu,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $MenuName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.Object[]]
        $OptionMenu,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $InputOptionMenu,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $CliCommand,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $JsonObfContainer
    )

    # Boolean for output and execution purposes if current option is designated to execute a command rather than change to a new menu.
    $selectionContainsCommand = $false
    $acceptableInput = @(foreach ($menuLine in $Menu)
    {
        # If FunctionCall property is present in current line then it is a command to execute if selected.
        if ($menuLine.FunctionCall)
        {
            $selectionContainsCommand = $true
        }

        # Return current menu option value.
        $menuLine.Option.Trim()
    })

    $userInput = $null

    # Loop until user inputs valid input.
    while ($acceptableInput -notcontains $userInput)
    {
        # Format custom breadcrumb prompt.
        Write-Host "`n"
        $breadCrumb = $MenuName.Trim('_')
        if ($breadCrumb.Length -gt 1)
        {
            if ($breadCrumb -ieq 'show options')
            {
                $breadCrumb = 'Show Options'
            }
            if ($MenuName)
            {
                # Handle specific case substitutions from what is ALL CAPS in interactive menu and then correct casing we want to appear in the Breadcrumb.
                $breadCrumbCorrectedCasing = [PSCustomObject] @{
                    json               = 'JSON'
                    awspolicy          = 'AWSPolicy'
                    wildcardsinglechar = 'WildcardSingleChar'
                }

                # Perform casing substitutions for any matches in $breadCrumbCorrectedCasing PSCustomObject properties.
                # Otherwise simply upper-case the first character and lower-case all remaining characters.
                $breadCrumbArray = @(foreach ($crumb in $breadCrumb.Split('_'))
                {
                    $breadCrumbCorrectedCasing.$crumb ? $breadCrumbCorrectedCasing.$crumb : $crumb.Substring(0,1).ToUpper() + $crumb.Substring(1).ToLower()
                })
                $breadCrumb = $breadCrumbArray -join '\'
            }
            $breadCrumb = '\' + $breadCrumb
        }

        # Output menu heading.
        $firstLine = "Choose one of the below "

        if ($breadCrumb)
        {
            $firstLine += ($breadCrumb.Trim('\') + ' ')
        }
        Write-Host "$firstLine" -NoNewline

        # Change color and verbiage if selection will execute command.
        if ($selectionContainsCommand)
        {
            Write-Host "options" -NoNewline -ForegroundColor Green
            Write-Host " to" -NoNewline
            Write-Host " APPLY" -NoNewline -ForegroundColor Green
            Write-Host " to current JSON document" -NoNewline
        }
        else
        {
            Write-Host "options" -NoNewline -ForegroundColor Yellow
        }
        Write-Host ":`n"

        foreach ($menuLine in $Menu)
        {
            $menuLineSpace     = $menuLine.LineHeader
            $menuLineOption    = $menuLine.Option
            $menuLineValue     = $menuLine.Description
            $menuLineAttribute = $menuLine.Attribute

            Write-Host $menuLineSpace -NoNewline

            # If not empty then include breadcrumb in $menuLineOption output (is not colored and will not affect user-input syntax).
            if ($breadCrumb -and $menuLineSpace.StartsWith('['))
            {
                Write-Host ($breadCrumb.ToUpper().Trim('\') + '\') -NoNewline
            }

            # Change color if selection will execute command.
            if ($selectionContainsCommand)
            {
                Write-Host $menuLineOption -NoNewline -ForegroundColor Green
            }
            else
            {
                Write-Host $menuLineOption -NoNewline -ForegroundColor Yellow
            }

            # Add additional coloring to string encapsulated by <> if it exists in $menuLineValue.
            if ($menuLineValue -cmatch '<.*>')
            {
                Write-Host "`t" -NoNewline

                $remainingMenuLineValue = $menuLineValue
                while ($remainingMenuLineValue -cmatch '<[^>]+>')
                {
                    $firstPart  = $remainingMenuLineValue.Substring(0,$remainingMenuLineValue.IndexOf($Matches[0]))
                    $middlePart = $remainingMenuLineValue.Substring(($firstPart.Length + 1),($Matches[0].Length - 2))

                    Write-Host $firstPart -NoNewline
                    Write-Host $middlePart -NoNewline -ForegroundColor Cyan

                    # Set $remainingMenuLineValue as remaining substring so additional highlighting (if present) can occur in current while loop.
                    $remainingIndex = $firstPart.Length + $middlePart.Length + 2
                    if ($remainingIndex -gt $remainingMenuLineValue.Length)
                    {
                        $remainingMenuLineValue = $null
                    }
                    else
                    {
                        $remainingMenuLineValue = $remainingMenuLineValue.Substring($remainingIndex)
                    }
                }

                # Output remaining $remainingMenuLineValue.
                Write-Host $remainingMenuLineValue -NoNewline
            }
            else
            {
                Write-Host "`t$menuLineValue" -NoNewline
            }

            # Output additional description attribute if defined.
            if ($menuLineAttribute)
            {
                Write-Host " $menuLineAttribute" -NoNewline -ForegroundColor Red
            }

            Write-Host ''
        }

        # Prompt for user input with custom breadcrumb prompt.
        Write-Host ''
        if (-not $userInput)
        {
            Write-Host ''
        }
        $userInput = ''

        while (-not $userInput)
        {
            # Output custom prompt.
            Write-Host "Invoke-SkyScalpel$breadCrumb> " -NoNewline -ForegroundColor Magenta

            # Get command(s) stored in -CliCommand input parameter and set as next $userInput. Otherwise get interactive user input.
            if (($CliCommand | Measure-Object).Count -gt 0)
            {
                # Retrieve next command stored in -CliCommand input parameter.
                $nextCliCommand = ([System.String] $CliCommand[0]).Trim()
                $CliCommand = $CliCommand | Select-Object -Skip 1

                # Set $nextCliCommand retrieved above as current $userInput.
                $userInput = $nextCliCommand

                # Write next command to simulate user entering next command (for display purposes only).
                Write-Host $userInput
            }
            else
            {
                # If parent function's -Command was defined on command line and -NoExit switch was not defined then output final ObfuscatedJsonDocument to stdout and then quit. Otherwise continue with interactive Invoke-SkyScalpel.
                $parentFunctionInvocation = (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly)
                if (($CliCommand.Count -eq 0) -and `
                    $parentFunctionInvocation.BoundParameters['Command'] -and `
                    (
                        $parentFunctionInvocation.BoundParameters['Quiet'].IsPresent -or `
                        -not $parentFunctionInvocation.BoundParameters['NoExit'].IsPresent
                    )
                )
                {
                    if ($parentFunctionInvocation.BoundParameters['Quiet'].IsPresent)
                    {
                        # Remove Write-Host and Start-Sleep proxy functions so that Write-Host and Start-Sleep cmdlets will be called during the remainder of the interactive Invoke-SkyScalpel session.
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep

                        # PowerShell has no way to negate an .IsPresent property for a [Switch] so setting it to $false boolean value will cause the desired effect.
                        $parentFunctionInvocation.BoundParameters['Quiet'] = $false

                        # Automatically run 'Show Options' so the user has context of what has successfully been executed.
                        $userInput  = 'show options'
                        $breadCrumb = 'Show Options'
                    }

                    # -NoExit wasn't specified and -Command was, so we will output the result back in the main while loop.
                    if (-not $parentFunctionInvocation.BoundParameters['NoExit'].IsPresent)
                    {
                        $userInput = 'quit'
                    }
                }
                else
                {
                    # Read next command from interactive user input.
                    $userInput = (Read-Host).Trim()
                }

                # Split interactive input into appropriate sub-commands if applicable.
                if ($userInput)
                {
                    $cliCommand = $userInput | Split-Command
                }

                if (($cliCommand | Measure-Object).Count -gt 1)
                {
                    # Reset $userInput so current While loop will be traversed once more and process $userInput command as a -CliCommand.
                    $userInput = ''
                }
                else
                {
                    $cliCommand = @()
                }
            }
        }

        # Trim any leading trailing slashes so it doesn't misinterpret it as a compound command unnecessarily.
        $userInput = $userInput.Trim('/\')

        # Cause $userInput of base menu level directories to automatically work.
        if (($menuLevel.ForEach( { $_.Option.Trim() } ) -contains $userInput.Split('/\')[0]) -and ($MenuName -ne ''))
        {
            # Prepend current $userInput to $CliCommand array and then set current $userInput to 'home' to automatically handle home directory traversal in multi-command fashion.
            $CliCommand = [System.Array] $userInput.TrimStart() + $CliCommand

            $userInput = 'home'
        }

        # Identify if there is any regex in current non-SET and non-OUT $userInput by removing all alphanumeric characters and select special characters.
        # Also handle special **, *** and **** user input use cases to randomly select ONE, ONE-per-menu-level-grouping or ALL eligible options, respectively,
        # in current menu to the deepest level until obfuscation is applied if sub-options are present.
        if ($userInput.Trim() -in @('**','***','****'))
        {
            # Extract and compute CLI command for all sub-paths with valid obfuscation options.
            $validSubPathOptionObjArr = (Get-Variable -Name "menuLevel$MenuName*").Where( { $_.Value.FunctionCall -ne $null } ).ForEach(
            {
                $curSubPathOption = $_

                # Extract current sub-path option's next menu level name for grouping purposes.
                $nextMenuLevel = $curSubPathOption.Name.Substring("menuLevel$MenuName".Length).TrimStart('_').Split('_')[0]

                # Compute current sub-path option's CLI command syntax.
                $curCliCommand = ($curSubPathOption.Name -replace '^menuLevel','Home' -replace '_','\') + '\' + (Get-Random -InputObject $curSubPathOption.Value.Option)

                # Return current sub-path object.
                [PSCustomObject] @{
                    NextMenuLevel = $nextMenuLevel
                    CliCommand    = $curCliCommand
                }
            } )

            # Return one, one-per-menu-level-grouping or all CLI commands extracted above.
            $cliOptionArr = switch ($userInput.Trim())
            {
                '**' {
                    # Return one random CLI command.
                    Get-Random -InputObject $validSubPathOptionObjArr.CliCommand
                }
                '***' {
                    # Group sub-path object(s) by extracted next menu level name.
                    $validSubPathOptionObjGrouped = $validSubPathOptionObjArr | Group-Object NextMenuLevel

                    # Return one random CLI command from each menu level grouping in shuffled order.
                    Get-Random -InputObject $validSubPathOptionObjGrouped.ForEach( { Get-Random -InputObject $_.Group.CliCommand } ) -Shuffle
                }
                '****' {
                    # Return all CLI command(s) in shuffled order.
                    Get-Random -InputObject $validSubPathOptionObjArr.CliCommand -Shuffle
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }

            # Append CLI option(s) to return to current menu after all CLI obfuscation is completed.
            $cliOptionArr = [System.Array] $cliOptionArr + ("Home$MenuName".Split('_').ForEach( { $_.Substring(0,1).ToString().ToUpper() + $_.Substring(1) } ) -join '\')

            # Split full array of CLI commands in $cliOptionArr into individual commands.
            $cliOptionArrSplit = $cliOptionArr.Split('\')

            # For initial CLI command, skip leading CLI options that just return to the current menu.
            if ($cliOptionArrSplit.ToLower().IndexOf($MenuName.TrimStart('_')) -ne -1)
            {
                $cliOptionArrSplit = $cliOptionArrSplit | Select-Object -Skip ($cliOptionArrSplit.ToLower().IndexOf($MenuName.TrimStart('_').ToLower()) + 1)
            }
            elseif ($cliOptionArrSplit[0] -eq 'Home')
            {
                $cliOptionArrSplit = $cliOptionArrSplit | Select-Object -Skip 1
            }

            # Prepend $cliOptionArrSplit to $CliCommand array.
            $CliCommand = [System.Array] $cliOptionArrSplit + $CliCommand

            # Return current menu response to re-display the current menuLevel options before the updated CliCommand values are input as automated user input.
            # This ordering is primarily for a better user experience visually when entering ** or *** input options.
            return [PSCustomObject] @{
                UserResponse     = $breadCrumb.Replace('\','_')
                JsonObfContainer = $JsonObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif (($userInput -ireplace '[a-z0-9\s+\\/-?]','') -and ($userInput.TrimStart() -inotmatch '^(SET|OUT|EXPORT) '))
        {
            # Create temporary userInputRegex and replace any simple wildcard with .* syntax.
            $userInputRegex = $userInput -csplit '\.\*' -creplace '\*','.*' -join '.*'

            # Prepend userInputRegex with ^ and append with $ if either character is not already present.
            if ($userInputRegex.Trim() -cnotmatch '^(\^|\.\*)')
            {
                $userInputRegex = '^' + $userInputRegex
            }
            if ($userInputRegex.Trim() -cnotmatch '(\$|\.\*)$')
            {
                $userInputRegex = $userInputRegex + '$'
            }

            # See if there are any filtered matches in the current menu.
            try
            {
                $menuFiltered = $acceptableInput.Where( { $_ } ) -imatch $userInputRegex
            }
            catch
            {
                # Output error message if Regular Expression causes error in above filtering step.
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }

            # If there are filtered matches in the current menu then randomly choose one for the UserInput value.
            if ($menuFiltered)
            {
                # Randomly select UserInput from filtered options.
                $userInput = (Get-Random -Input $menuFiltered).Trim()

                # Output randomly chosen option (and filtered options selected from) if more than one options were returned from regex.
                if ($menuFiltered.Count -gt 1)
                {
                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    if ($selectionContainsCommand)
                    {
                        $colorToOutput = 'Green'
                    }
                    else
                    {
                        $colorToOutput = 'Yellow'
                    }

                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $userInput -NoNewline -ForegroundColor $colorToOutput
                    write-host ' from the following filtered options: ' -NoNewline

                    for ($i=0; $i -lt $menuFiltered.Count - 1; $i++)
                    {
                        Write-Host $menuFiltered[$i].Trim() -NoNewline -ForegroundColor $colorToOutput
                        Write-Host ', ' -NoNewline
                    }
                    Write-Host $menuFiltered[$menuFiltered.Count - 1].Trim() -ForegroundColor $colorToOutput
                }
            }
        }

        if ($InputOptionMenu.Exit.Option -icontains $userInput)
        {
            # Return next menu response from $userInput and command container $JsonObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                JsonObfContainer = $JsonObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($InputOptionMenu.BackMenu.Option -icontains $userInput)
        {
            # Commands like 'back' that will return user to previous interactive menu.
            if ($breadCrumb.Contains('\'))
            {
                $userInput = $breadCrumb.Substring(0,$breadCrumb.LastIndexOf('\')).Replace('\','_')
            }
            else
            {
                $userInput = ''
            }

            # Return next menu response from $userInput and command container $JsonObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                JsonObfContainer = $JsonObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($InputOptionMenu.HomeMenu.Option -icontains $userInput)
        {
            # Return next menu response from $userInput and command container $JsonObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                JsonObfContainer = $JsonObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($userInput.ToLower().StartsWith('set '))
        {
            # Extract $userInputOptionName and $userInputOptionValue from $userInput SET command.
            $userInputOptionName  = $null
            $userInputOptionValue = $null
            $hasError = $false

            $userInputMinusSet = $userInput.Substring(4).Trim()
            if (-not $userInputMinusSet.Contains(' '))
            {
                # No value defined after input option name.
                $hasError = $true
                $userInputOptionName = $userInputMinusSet.Trim()
            }
            else
            {
                $userInputOptionName  = $userInputMinusSet.Substring(0,$userInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $userInputOptionValue = $userInputMinusSet.Substring($userInputMinusSet.IndexOf(' ')).Trim()
            }

            # Validate that $userInputOptionName is defined in settable input options defined in -OptionMenu.
            $settableInputOption = $OptionMenu.Where( { $_.Settable } ).Name
            if ($userInputOptionName -in $settableInputOption)
            {
                # Perform separate validation for $userInputOptionValue before setting value.
                if ($userInputOptionValue.Length -eq 0)
                {
                    # No OPTIONVALUE was entered after OPTIONNAME.
                    $hasError = $true

                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host ' No value was entered after ' -NoNewline
                    Write-Host $userInputOptionName.ToUpper() -NoNewline -ForegroundColor Cyan
                    Write-Host '.' -NoNewline
                }
                else
                {
                    switch ($userInputOptionName.ToLower())
                    {
                        'jsondocumentpath' {
                            if ($userInputOptionValue -and ((Test-Path $userInputOptionValue) -or ($userInputOptionValue -match '^(http|https):[/\\]')))
                            {
                                # Reset JsonDocument in case it contained a value.
                                $jsonDocument = ''

                                # Check if -JsonDocumentPath input parameter is a URL or a directory.
                                if ($userInputOptionValue -match '^(http|https):[/\\]')
                                {
                                    # JsonDocumentPath is a URL.

                                    # Download content from remote location.
                                    $jsonDocument = (New-Object Net.WebClient).DownloadString($userInputOptionValue)

                                    # Build new obfuscation container.
                                    $JsonObfContainer = New-ObfuscationContainer -JsonDocument $jsonDocument

                                    # Set user-input JSONDOCUMENTPATH value into JsonDocumentPath property of newly-created obfuscation container.
                                    $JsonObfContainer.JsonDocumentPath = $userInputOptionValue

                                    Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                    Write-Host 'JsonDocumentPath' -NoNewline -ForegroundColor Yellow
                                    Write-Host ' (as URL):' -ForegroundColor Cyan
                                    Write-Host $JsonObfContainer.JsonDocumentPath -ForegroundColor Magenta
                                }
                                elseif ((Get-Item $userInputOptionValue) -is [System.IO.DirectoryInfo])
                                {
                                    # JsonDocumentPath does not exist.
                                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                    Write-Host ' Path is a directory instead of a file (' -NoNewline
                                    Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                                    Write-Host ").`n" -NoNewline
                                }
                                else
                                {
                                    # Build new obfuscation container with file content from user-input -JsonDocumentPath parameter.
                                    $JsonObfContainer = New-ObfuscationContainer -JsonDocumentPath (Resolve-Path $userInputOptionValue).Path

                                    # Set user-input JSONDOCUMENTPATH value into JsonDocumentPath property of newly-created obfuscation container.
                                    $JsonObfContainer.JsonDocumentPath = (Resolve-Path $userInputOptionValue).Path

                                    Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                    Write-Host 'JsonDocumentPath' -NoNewline -ForegroundColor Yellow
                                    Write-Host ':' -ForegroundColor Cyan
                                    Write-Host $JsonObfContainer.JsonDocumentPath -ForegroundColor Magenta
                                }
                            }
                            else
                            {
                                # JsonDocumentPath not found (failed Test-Path).
                                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                Write-Host ' Path not found (' -NoNewline
                                Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                                Write-Host ").`n" -NoNewline
                            }
                        }
                        'jsondocument' {
                            $jsonDocument = $userInputOptionValue

                            # Build new obfuscation container.
                            $JsonObfContainer = New-ObfuscationContainer -JsonDocument $jsonDocument

                            # Set N/A value in JsonDocumentPath property of newly-created obfuscation container.
                            $JsonObfContainer.JsonDocumentPath = 'N/A'

                            Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                            Write-Host 'JsonDocument' -NoNewline -ForegroundColor Yellow
                            Write-Host ':' -ForegroundColor Cyan
                            Out-JsonObject -InputObject $JsonObfContainer.JsonDocument -Format raw
                        }
                        default {
                            Write-Error "An invalid OPTIONNAME ($userInputOptionName) was passed to switch block."

                            exit
                        }
                    }
                }
            }
            else
            {
                $hasError = $true

                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' OPTIONNAME ' -NoNewline
                Write-Host $userInputOptionName.ToUpper() -NoNewline -ForegroundColor Cyan
                Write-Host ' is not a settable option.' -NoNewline

                Write-Host ' Enter' -NoNewline
                Write-Host ' SHOW OPTIONS' -NoNewline -ForegroundColor Yellow
                Write-Host ' for more details.' -NoNewline
            }

            # Output additional information if any user input error occurred above.
            if ($hasError)
            {
                if ($userInputOptionName -in $settableInputOption)
                {
                    Write-Host "`n       Correct syntax is" -NoNewline
                    Write-Host " SET $($userInputOptionName.ToUpper()) VALUE" -NoNewline -ForegroundColor Green
                    Write-Host '.' -NoNewline
                }
                else
                {
                    # Output all settable options if invalid input was entered.
                    if($settableInputOption.Count -gt 1)
                    {
                        $message = 'Valid settable options include:'
                    }
                    else
                    {
                        $message = 'Valid settable option includes:'
                    }
                    Write-Host "`n       $message " -NoNewline

                    # Output yellow-colored options corresponding to settable option(s).
                    for ($i = 0; $i -lt $settableInputOption.Count - 1; $i++)
                    {
                        Write-Host $settableInputOption[$i].ToUpper() -NoNewline -ForegroundColor Yellow
                        Write-Host ', ' -NoNewline
                    }
                    Write-Host $settableInputOption[$i].ToUpper() -NoNewline -ForegroundColor Yellow
                }
            }
        }
        elseif ($acceptableInput -icontains $userInput)
        {
            # User input matches $acceptableInput extracted from the current $Menu, so decide if:
            # 1) an obfuscation function needs to be called and remain in current interactive prompt, or
            # 2) return value to enter into a new interactive prompt.

            # Format breadcrumb trail to successfully retrieve the next interactive prompt.
            $userInput = $breadCrumb.Trim('\').Replace('\','_') + '_' + $userInput
            if ($breadCrumb.StartsWith('\'))
            {
                $userInput = '_' + $userInput
            }

            # If the current selection does not contain a command to execute then return to go to another menu. Otherwise continue to execute command.
            if (-not $selectionContainsCommand)
            {
                # User input is not command but menu, so return input to go to next menu and return command container $JsonObfContainer defined or updated in this function.
                return [PSCustomObject] @{
                    UserResponse     = $userInput
                    JsonObfContainer = $JsonObfContainer
                    CliCommand       = $CliCommand
                }
            }

            # Make sure user has entered command or path to script.
            if ($JsonObfContainer.JsonDocument -ne $null)
            {
                # Iterate through lines in $Menu to extract command for the current selection in $userInput.
                foreach ($menuLine in $Menu)
                {
                    if ($menuLine.Option.Trim(' ') -eq $userInput.Substring($userInput.LastIndexOf('_') + 1))
                    {
                        $selectedMenuLine = $menuLine

                        continue
                    }
                }

                # Validate that user has set JSONDOCUMENT or JSONDOCUMENTPATH (by seeing if ObfuscatedJsonDocument property is empty).
                if (-not $JsonObfContainer.JsonDocument)
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot execute obfuscation commands without setting JsonDocument or JsonDocumentPath values in SHOW OPTIONS menu. Set these by executing" -NoNewline
                    Write-Host ' SET JSONDOCUMENT json_document' -NoNewline -ForegroundColor Green
                    Write-Host ' or' -NoNewline
                    Write-Host ' SET JSONDOCUMENTPATH path_to_json_document_file_or_URL' -NoNewline -ForegroundColor Green
                    Write-Host '.'

                    continue
                }

                # Execute command(s) stored in FunctionCall property of current menu line selected by user.
                Get-Random -InputObject $selectedMenuLine.FunctionCall -Count ($selectedMenuLine.FunctionCall | Measure-Object).Count | ForEach-Object {
                    $functionCallScriptBlock = $_

                    # Track previous layer count to ascertain if obfuscation layer is successfully applied in below switch block.
                    $prevLayer = $JsonObfContainer.Layer

                    # Execute current FunctionCall property value, capturing elapsed execution time for output purposes.
                    $functionCallExecElapsedTime = Measure-Command -Expression {
                        # Set $jsonDocument variable since command in current FunctionCall property value references this variable as input.
                        $jsonDocument = $JsonObfContainer.JsonDocument
                        $obfuscatedJsonDocumentTokenized = . ([ScriptBlock]::Create($functionCallScriptBlock))
                    }

                    # Output elapsed time for FunctionCall ScriptBlock invocation above.
                    Write-Host "`nElapsed Time: " -NoNewline
                    Write-Host $functionCallExecElapsedTime -ForegroundColor White

                    # Throw warning message if no obfuscation layer was successfully applied in above switch block.
                    if ($JsonObfContainer.JsonDocument -ceq (-join$obfuscatedJsonDocumentTokenized.Content))
                    {
                        Write-Host "`nWARNING:" -NoNewline -ForegroundColor Red
                        Write-Host ' No obfuscation applied due to lack of eligibility or low randomization percentage.'
                    }
                    else
                    {
                        # Add current obfuscation layer in History property and update relevant properties in main obfuscation object.
                        $JsonObfContainer = $JsonObfContainer | Add-ObfuscationLayer -JsonDocumentTokenized $obfuscatedJsonDocumentTokenized

                        # Convert UserInput to CLI syntax then store in CliSyntax property.
                        $cliSyntax = $userInput.Trim('_ ').Replace('_','\')

                        # Store CLI syntax, full Command Line Syntax and Function values in CliSyntax, CommandLineSyntax and Function properties, respectively.
                        $JsonObfContainer.History[-1].CliSyntax += $cliSyntax
                        $JsonObfContainer.History[-1].CommandLineSyntax = $functionCallScriptBlock.ToString().Replace($requiredFunctionPrefixArgumentsToHideFromUI,'').Replace($requiredFunctionSuffixArgumentsToHideFromUI,'')
                        $JsonObfContainer.History[-1].Function = $functionCallScriptBlock.ToString().Split(' ').Where( { $_ -and (Get-Command -CommandType Function -Name $_ -ErrorAction SilentlyContinue).Name } )[0]

                        # Output syntax of CLI syntax and full command executed in above Switch block.
                        Write-Host "`nExecuted:"
                        Write-Host '  CLI:  ' -NoNewline
                        Write-Host $JsonObfContainer.History[-1].CliSyntax -ForegroundColor Cyan

                        # Split out $jsonDocument so it can be output in different color.
                        Write-Host '  Full: ' -NoNewline
                        ($JsonObfContainer.History[-1].CommandLineSyntax -isplit '\$jsonDocument').Where( { $_ } ).ForEach(
                        {
                            Write-Host $_ -NoNewline -ForegroundColor Cyan
                        } )
                        Write-Host ''

                        # Output obfuscation result.
                        Write-Host "`nResult:`t"
                        Out-JsonObject -InputObject $JsonObfContainer.History[-1].JsonDocumentTokenized
                    }
                }
            }
        }
        else
        {
            if ($InputOptionMenu.ShowHelp.Option -icontains $userInput)
            {
                Show-HelpMenu -InputOptionMenu $InputOptionMenu
            }
            elseif ($InputOptionMenu.ShowOption.Option -icontains $userInput)
            {
                Show-OptionsMenu -Menu $OptionMenu -JsonObfContainer $JsonObfContainer
            }
            elseif ($InputOptionMenu.OutputTree.Option -icontains $userInput)
            {
                if ($JsonObfContainer.JsonDocument)
                {
                    Write-Host ($JsonObfContainer.JsonDocument.StartsWith(' ') ? '' : "`n")
                    Out-JsonObject -InputObject $JsonObfContainer.History[-1].JsonDocumentTokenized -SkipModificationHighlighting
                }
                else
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot print because you have not set JsonDocument or JsonDocumentPath.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set JsonDocument or JsonDocumentPath."
                }
            }
            elseif ($InputOptionMenu.Tutorial.Option -icontains $userInput)
            {
                Show-Tutorial
            }
            elseif ($InputOptionMenu.ClearScreen.Option -icontains $userInput)
            {
                Clear-Host
            }
            elseif ($InputOptionMenu.FindEvil.Option -icontains $userInput)
            {
                if ($JsonObfContainer.JsonDocument)
                {
                    # Evaluate all Detections in Find-Evil function for current JSON document, capturing elapsed execution time for output purposes.
                    $findEvilElapsedTime = Measure-Command -Expression {
                        $detectionSummary = Find-Evil -JsonDocument $JsonObfContainer.JsonDocument -Summarize
                    }

                    # Output elapsed time for Detection evaluation above.
                    Write-Host "`nElapsed Time: " -NoNewline
                    Write-Host $findEvilElapsedTime -ForegroundColor White

                    # Output summary of Detection hit(s).
                    if ($detectionSummary.DetectionCount -eq 0)
                    {
                        # Output warning message if no Detection hits are present.
                        Write-Host "`nWARNING:" -NoNewline -ForegroundColor Red
                        Write-Host ' No detections matched ObfuscatedJsonDocument.'
                    }
                    else
                    {
                        # Output syntax of CLI syntax and full command executed in above Switch block.
                        Write-Host "`nExecuted:"
                        Write-Host '  CLI:  ' -NoNewline
                        Write-Host 'FIND-EVIL' -ForegroundColor Cyan
                        Write-Host '  Full: ' -NoNewline
                        Write-Host 'Find-Evil -Summarize | Show-EvilSummary' -ForegroundColor Cyan

                        # Output summary of Detection hit(s).
                        Write-Host "`nResult:`t"
                        Show-EvilSummary -DetectionSummary $detectionSummary -SuppressPadding
                    }  
                }
                else
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot evaluate detections because you have not set JSONDOCUMENT or JSONDOCUMENTPATH.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set JSONDOCUMENT or JSONDOCUMENTPATH."
                }
            }
            elseif ($InputOptionMenu.ResetObfuscation.Option -icontains $userInput)
            {
                if (-not $JsonObfContainer.JsonDocument)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " ObfuscatedJsonDocument has not been set. There is nothing to reset."
                }
                elseif ($JsonObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedJsonDocument. There is nothing to reset."
                }
                else
                {
                    # Build new obfuscation container from existing obfuscation container original values.
                    $prevJsonDocumentPath = $JsonObfContainer.JsonDocumentPath
                    $JsonObfContainer = New-ObfuscationContainer -JsonDocument $JsonObfContainer.History[0].JsonDocument

                    # Set previous JsonDocumentPath value in JsonDocumentPath property of newly-created obfuscation container.
                    $JsonObfContainer.JsonDocumentPath = $prevJsonDocumentPath

                    Write-Host "`n`nSuccessfully reset ObfuscatedJsonDocument." -ForegroundColor Cyan
                }
            }
            elseif ($InputOptionMenu.UndoObfuscation.Option -icontains $userInput)
            {
                if (-not $JsonObfContainer.JsonDocument)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " ObfuscatedJsonDocument has not been set. There is nothing to undo."
                }
                elseif ($JsonObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedJsonDocument. There is nothing to undo."
                }
                else
                {
                    # Remove last obfuscation layer in History property and update relevant properties in main obfuscation object.
                    $JsonObfContainer = $JsonObfContainer | Remove-ObfuscationLayer

                    Write-Host "`n`nSuccessfully removed last obfuscation layer from ObfuscatedJsonDocument." -ForegroundColor Cyan
                }
            }
            elseif (([System.Array] $InputOptionMenu.OutputToDisk.Option + $InputOptionMenu.ExportToDisk.Option) -icontains $userInput.Trim().Split(' ')[0])
            {
                # Handle verbiage if $userInput is OUT versus EXPORT for ObfuscatedJsonDocument output versus $jsonObfContainer CliXml export, respectively.
                if ($userInput.Trim().Split(' ')[0] -ieq 'out')
                {
                    $outputObj = [PSCustomObject] @{
                        Type              = 'output'
                        StringPresent     = 'output'
                        StringPresentFull = 'output ObfuscatedJsonDocument'
                        StringPastFull    = 'output ObfuscatedJsonDocument'
                        DefaultOutputFile = 'Obfuscated_JSON_Document.txt'
                    }
                }
                else
                {
                    $outputObj = [PSCustomObject] @{
                        Type              = 'export'
                        StringPresent     = 'export'
                        StringPresentFull = 'export $jsonObfContainer'
                        StringPastFull    = 'exported $jsonObfContainer'
                        DefaultOutputFile = 'Obfuscated_JSON_Document_Container.clixml'
                    }
                }

                if (-not $JsonObfContainer.JsonDocument)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " ObfuscatedJsonDocument has not been set. There is nothing to $($outputObj.StringPresent)."
                }
                elseif ($JsonObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:"                                               -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS"                                              -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedJsonDocument."
                }
                else
                {
                    # Get file path information from compound user input (e.g. OUT C:\FILENAME.TXT, EXPORT C:\FILENAME.CLIXML).
                    if ($userInput.Trim().Split(' ').Count -gt 1)
                    {
                        # Get file path information from user input.
                        $userInputOutputFilePath = $userInput.Trim().Substring($userInput.Trim().IndexOf(' ')).Trim()
                        Write-Host ''
                    }
                    else
                    {
                        # Get file path information from user interactively.
                        $userInputOutputFilePath = Read-Host "`n`nEnter path for $($outputObj.Type) file (or leave blank for default)"
                    }

                    # Set default file path as Downloads folder depending on OS.
                    $defaultOutputFilePath = Join-Path -Path (($IsLinux -or $IsMacOS) ? $env:HOME : $env:USERPROFILE) -ChildPath 'Downloads'

                    # Decipher if user input a full file path, just a file name or nothing (default).
                    if (-not $userInputOutputFilePath.Trim())
                    {
                        # Set default output file path.
                        $outputFilePath = Join-Path -Path $defaultOutputFilePath -ChildPath $outputObj.DefaultOutputFile
                    }
                    elseif ($userInputOutputFilePath -notmatch '[/\\]')
                    {
                        # User input is not a file path so treat it as a filename and use current directory of this script.
                        $outputFilePath = Join-Path -Path $defaultOutputFilePath -ChildPath $userInputOutputFilePath.Trim()
                    }
                    else
                    {
                        # User input is a full file path.
                        $outputFilePath = $userInputOutputFilePath.Trim()
                    }

                    # Output/export to disk.
                    switch ($outputObj.Type)
                    {
                        'output' {
                            # Write ObfuscatedJsonDocument out to disk.
                            Set-Content -Path $outputFilePath -Value $JsonObfContainer.JsonDocument
                        }
                        'export' {
                            # Export $JsonObfContainer CliXml to disk.
                            Export-CliXml -InputObject $JsonObfContainer -Path $outputFilePath
                        }
                        defaut
                        {
                            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                        }
                    }

                    # Output if file write is successful or not. If successful then use default text file editor to open file.
                    if (Test-Path $outputFilePath)
                    {
                        # Add CliSyntax record.
                        $JsonObfContainer.History[-1].CliSyntax += "$($userInput.Trim().Split(' ')[0].ToLower()) $outputFilePath"

                        Write-Host "`nSuccessfully $($outputObj.StringPastFull) to" -NoNewline -ForegroundColor Cyan
                        Write-Host " $outputFilePath"                               -NoNewline -ForegroundColor Yellow
                        Write-Host "." -ForegroundColor Cyan

                        # Set current command in clipboard depending on OS.
                        if ($IsMacOS)
                        {
                            # Open is a native MacOS binary used for opening user's default text editor for viewing and editing text files.
                            $openPath = (Get-Command -Name open -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($openPath -and (Test-Path -Path $openPath))
                            {
                                # Notes from the open man page:
                                #   -e  Causes the file to be opened with /Applications/TextEdit
                                #   -t  Causes the file to be opened with the default text editor, as determined via LaunchServices
                                # Not defining either of these arguments opens the document in the default application for its type (as determined by LaunchServices).

                                # Defaulting to -t argument to force the user's default text editor to open the file.
                                # This is to prevent the default application from potentially executing the file based on the user's defined file extension when outputting the file.
                                Start-Process -FilePath $openPath -ArgumentList "-t `"$($outputFilePath.Replace('"','\"'))`""
                            }
                            else
                            {
                                Write-Warning "Native 'open' binary not found. This binary is required on macOS to properly handle launching current user's default text editor to open newly created output file."
                            }
                        }
                        elseif ($IsLinux)
                        {
                            # Gedit is the default text editor for the GNOME Desktop for viewing and editing text files.
                            $geditPath = (Get-Command -Name gedit -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($geditPath -and (Test-Path -Path $geditPath))
                            {
                                Start-Process -FilePath $geditPath -ArgumentList "`"$($outputFilePath.Replace('"','\"'))`"" -RedirectStandardError 'stderr'
                            }
                            else
                            {
                                Write-Warning "Native 'gedit' binary not found. This binary is the default text editor for the GNOME Desktop for viewing and editing text files."
                            }
                        }
                        elseif ($IsWindows -or -not ($IsLinux -or $IsMacOS))
                        {
                            # Query current user's default text editor from registry.
                            # Reference: https://stackoverflow.com/questions/61599183/powershell-opening-a-file-in-default-txt-editor
                            $defaultTextEditorRegKeyProp  =  Get-ItemProperty -Path 'Registry::\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice'
                            $defaultTextEditorRegKeyValue = (Get-ItemProperty -Path "Registry::\HKEY_CLASSES_ROOT\$($defaultTextEditorRegKeyProp.ProgId)\shell\open\command").'(default)'
                            $defaultTextEditorPath = $defaultTextEditorRegKeyValue.Split('%')[0].Trim()

                            # Use current user's default text editor to open output file if binary is present. Otherwise default to notepad.exe.
                            if (Test-Path $defaultTextEditorPath)
                            {
                                $textEditorPath = $defaultTextEditorPath

                                Start-Process -FilePath $textEditorPath -ArgumentList $outputFilePath
                            }
                            else
                            {
                                # Notepad.exe is a native Windows binary used for viewing and editing text files.
                                $notepadPath = (Get-Command -Name notepad.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                                if ($notepadPath -and (Test-Path -Path $notepadPath))
                                {
                                    Start-Process -FilePath $notepadPath -ArgumentList $outputFilePath
                                }
                                else
                                {
                                    Write-Warning "Native 'notepad.exe' binary not found. This binary is the default text editor for viewing text files."
                                }
                            }
                        }
                    }
                    else
                    {
                        Write-Host "`nERROR: Unable to $($outputObj.StringPresentFull) to" -NoNewline -ForegroundColor Red
                        Write-Host " $outputFilePath" -NoNewline -ForegroundColor Yellow
                    }
                }
            }
            elseif ($InputOptionMenu.CopyToClipboard.Option -icontains $userInput)
            {
                if ($JsonObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedJsonDocument."
                }
                elseif ($JsonObfContainer.JsonDocument)
                {
                    # Copy ObfuscatedJsonDocument to clipboard.
                    # Try-Catch block introduced since PowerShell v2.0 without -STA defined will not be able to perform clipboard functionality.
                    try
                    {
                        # Set current command in clipboard depending on OS.
                        if ($IsMacOS)
                        {
                            # pbcopy is a native macOS binary used for copying content to the clipboard since no cmdlet exists in PowerShell Core.
                            $pbcopyPath = (Get-Command -Name pbcopy -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($pbcopyPath -and (Test-Path -Path $pbcopyPath))
                            {
                                $JsonObfContainer.JsonDocument | . $pbcopyPath
                            }
                            else
                            {
                                Write-Warning "Native 'pbcopy' binary not found. This binary is required on macOS to copy text to clipboard since Set-Clipboard cmdlet does not exist in PowerShell Core."
                            }
                        }
                        elseif ($IsLinux)
                        {
                            # xclip is a non-native Linux binary used for copying content to the clipboard since no cmdlet exists in PowerShell Core. It must be manually installed to use the 'clip' functionality in Invoke-SkyScalpel.
                            $xclipPath = (Get-Command -Name xclip -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($xclipPath -and (Test-Path -Path $xclipPath))
                            {
                                # Start xclip as background job since it takes over a minute to run on some Linux distributions even though the clipboard content is set immediately.
                                $jobName = 'Invoke-SkyScalpel_xclip'

                                # Remove any previous jobs for this function.
                                Remove-Job -Name $jobName -ErrorAction SilentlyContinue

                                # Start new xclip job in background to continue without waiting.
                                Start-Job -Name $jobName -ScriptBlock ([ScriptBlock]::Create("echo '$($JsonObfContainer.JsonDocument.Replace("'","''"))' | . $xclipPath -in -selection clipboard")) | Out-Null
                            }
                            else
                            {
                                Write-Warning "Native 'xclip' binary not found. This binary is required on Linux to copy text to clipboard since Set-Clipboard cmdlet does not exist in PowerShell Core. Install xclip on this system. E.g. sudo apt install xclip"
                            }
                        }
                        elseif ($IsWindows -or -not ($IsLinux -or $IsMacOS))
                        {
                            # Differentiate between clipboard options in PowerShell and PowerShell Core.
                            if ($PSVersionTable.PSVersion.Major -le 5)
                            {
                                $null = [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
                                [System.Windows.Forms.Clipboard]::SetText($JsonObfContainer.JsonDocument)
                            }
                            else
                            {
                                Set-Clipboard -Value $JsonObfContainer.JsonDocument
                            }
                        }

                        Write-Host "`n`nSuccessfully copied ObfuscatedJsonDocument to clipboard." -ForegroundColor Cyan
                    }
                    catch
                    {
                        $errorMessage = "Clipboard functionality will not work in PowerShell version $($PSVersionTable.PSVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."

                        if ((Get-Command -Name Write-Host).CommandType -ne 'Cmdlet')
                        {
                            # Retrieving Write-Host and Start-Sleep Cmdlets to get around the current proxy functions of Write-Host and Start-Sleep that are overloaded if -Quiet flag was used.
                            . (Get-Command -Name Write-Host -CommandType Cmdlet) "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            . (Get-Command -Name Write-Host -CommandType Cmdlet) $errorMessage -NoNewline

                            if ($JsonObfContainer.History.CliSyntax)
                            {
                                . (Get-Command -Name Start-Sleep -CommandType Cmdlet) -Seconds 2
                            }
                        }
                        else
                        {
                            Write-Host "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            Write-Host $errorMessage

                            if ($JsonObfContainer.History.CliSyntax)
                            {
                                Start-Sleep -Seconds 2
                            }
                        }
                    }

                    $JsonObfContainer.History[-1].CliSyntax += 'clip'
                }
                elseif (-not $JsonObfContainer.JsonDocument)
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedJsonDocument." -NoNewline
                }
            }
            else
            {
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewline
                Write-Host " HELP" -NoNewline -ForegroundColor Yellow
                Write-Host " for more information."

                # If the failed input was part of $CliCommand then cancel out the rest of the concatenated command so it is not further processed.
                if ($CliCommand.Count -gt 0)
                {
                    $CliCommand = @()
                }

                # Output all available/acceptable options for current menu if invalid input was entered.
                if ($acceptableInput.Count -gt 1)
                {
                    $message = 'Valid options for current menu include:'
                }
                else
                {
                    $message = 'Valid option for current menu includes:'
                }
                Write-Host "       $message " -NoNewline

                $counter=0
                foreach ($option in $acceptableInput)
                {
                    $counter++

                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    $colorToOutput = $selectionContainsCommand ? 'Green' : 'Yellow'

                    Write-Host $option -NoNewline -ForegroundColor $colorToOutput
                    if (($counter -lt $acceptableInput.Length) -and $option)
                    {
                        Write-Host ', ' -NoNewline
                    }
                }
                Write-Host ''
            }
        }
    }

    # Return next menu response from $userInput and command container $JsonObfContainer defined or updated in this function.
    [PSCustomObject] @{
        UserResponse     = $userInput
        JsonObfContainer = $JsonObfContainer
        CliCommand       = $CliCommand
    }
}


function Show-OptionsMenu
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-OptionsMenu
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-OptionsMenu displays color-coded options menu for Invoke-SkyScalpel function.

.PARAMETER Menu

Specifies object containing list of available menu option values and descriptions to display.

.PARAMETER JsonObfContainer

Specifies obfuscation container from which relevant values will be extracted and displayed about original and current version of JSON document.

.EXAMPLE

C:\PS> Show-OptionsMenu

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Menu,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $JsonObfContainer
    )

    # Set line header for consistent user experience.
    $lineHeader = '[*] '

    # Set JSON document size limit for more concise output formatting.
    $jsonDocumentDisplaySizeLimit = 100

    # Output menu.
    Write-Host "`n`nSHOW OPTIONS" -NoNewline -ForegroundColor Cyan
    Write-Host ' ::' -NoNewline
    Write-Host ' Yellow' -NoNewline -ForegroundColor Yellow
    Write-Host ' options can be set by entering' -NoNewline
    Write-Host ' SET OPTIONNAME VALUE' -NoNewline -ForegroundColor Green
    Write-Host ".`n"

     # Update each menu option value from obfuscation container before displaying.
    foreach ($option in $Menu)
    {
        switch ($option.Name)
        {
            'JsonDocumentPath' {
                $option.Value = $JsonObfContainer.JsonDocumentPath
            }
            'JsonDocument' {
                $option.Value = ($JsonObfContainer.Layer -gt 0) ? $JsonObfContainer.History[0].JsonDocument : $JsonObfContainer.JsonDocument
            }
            'CommandlineSyntax' {
                $option.Value = ($JsonObfContainer.JsonDocumentSize -gt 0) ? $JsonObfContainer.History.CliSyntax : $null
            }
            'ExecutionCommands' {
                $option.Value = ($JsonObfContainer.JsonDocumentSize -gt 0) ? $JsonObfContainer.History.CommandLineSyntax : $null
            }
            'ObfuscatedJsonDocument' {
                $option.Value = ($JsonObfContainer.Layer -gt 0) ? $JsonObfContainer.JsonDocument : $null
            }
            'Length' {
                $option.Value = $JsonObfContainer.JsonDocument ? $JsonObfContainer.JsonDocumentSize : $null
            }
            'Depth' {
                $option.Value = $JsonObfContainer.JsonDocument ? $JsonObfContainer.JsonDocumentDepth : $null
            }
            'DetectionScore' {
                $option.Value = $JsonObfContainer.JsonDocument ? (Find-Evil -JsonDocument $JsonObfContainer.JsonDocument -Summarize).TotalScore : $null
            }
            'DetectionCount' {
                $option.Value = $JsonObfContainer.JsonDocument ? (Find-Evil -JsonDocument $JsonObfContainer.JsonDocument -Summarize).DetectionCount : $null
            }
            default {
                Write-Error "Unhandled menu item in $($MyInvocation.MyCommand.Name) function: $_"

                exit
            }
        }

        # Output settable options as Yellow.
        Write-Host $lineHeader -NoNewline
        if ($option.Settable)
        {
            Write-Host $option.Name -NoNewline -ForegroundColor Yellow
        }
        else
        {
            Write-Host $option.Name -NoNewline
        }
        Write-Host ': ' -NoNewline
        
        # Handle coloring and multi-value output for specific menu values.
        switch ($option.Name)
        {
            'Length' {
                Write-Host $option.Value -ForegroundColor Cyan
            }
            'Depth' {
                Write-Host $option.Value -ForegroundColor Cyan
            }
            'JsonDocument' {
                # Output JsonDocument (unless it is not yet defined).
                if ($option.Value)
                {
                    Out-JsonObject -InputObject $option.Value -SkipModificationHighlighting -Format raw
                }
                else
                {
                    Write-Host ''
                }
            }
            'CommandLineSyntax' {
                # CliSyntax output.

                # First set potentially-null CLI field values of -Command and -JsonDocumentPath/-JsonDocument.

                # Set -Command field value if it exists.
                $commandSyntax = $null
                if ($option.Value)
                {
                    # Trim the beginning of adjacent command values that share similar starting paths.
                    # E.g. instead of displaying OBFUSCATE\JSON\UNICODE\1,OBFUSCATE\JSON\UNICODE\2 display OBFUSCATE\JSON\UNICODE\1,2.
                    $lastValuePath = $null
                    $commandSyntax = foreach ($curValue in $option.Value)
                    {
                        # Extract leading path of obfuscation command values (excluding non-obfuscation commands like OUT command, etc. where whitespace is present in the command).
                        if ($curValue.Contains('\') -and -not $curValue.Contains(' '))
                        {
                            $curValuePath = $curValue.Substring(0, $curValue.LastIndexOf('\') + 1)

                            # If current command starts with the same path as the last command then remove matching portion of command for simpler output formatting.
                            if ($curValue.StartsWith($lastValuePath))
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Green'; Value = $curValue.Substring($lastValuePath.Length).Replace("'","''") }
                            }
                            else
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Green'; Value = $curValue.Replace("'","''") }
                            }

                            # Keep track of value path for evaluation in following foreach iterations.
                            $lastValuePath = $curValuePath
                        }
                        else
                        {
                            # Output non-obfuscation command as yellow instead of green.
                            [PSCustomObject] @{ ForegroundColor = 'Yellow'; Value = $curValue.Replace("'","''") }
                        }

                        # Set comma delimiter object between each command value.
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = ',' }
                    }

                    # Remove trailing comma since it is not required.
                    $commandSyntax = $commandSyntax[0..(($commandSyntax | Measure-Object).Count - 2)]

                    $commandSyntax = @(
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = " -Command '" }
                        $commandSyntax
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = "'"           }
                    )
                }

                # Set -JsonDocumentPath/-JsonDocument field value if it exists.
                $setSyntax = $null
                if ($JsonObfContainer.JsonDocumentPath -and ($JsonObfContainer.JsonDocumentPath -ne 'N/A'))
                {
                    # Encapsulate JsonDocumentPath with quotes if whitespace is present in path.
                    if ($JsonObfContainer.JsonDocumentPath.Contains(' '))
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = " -JsonDocumentPath '"             }
                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $JsonObfContainer.JsonDocumentPath }
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = "'"                                }
                        )
                    }
                    else
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';        Value = " -JsonDocumentPath "              }
                            [PSCustomObject] @{ ForegroundColor = 'DarkMagenta'; Value = $JsonObfContainer.JsonDocumentPath }
                        )
                    }
                }
                elseif ($JsonObfContainer.History -and $JsonObfContainer.History[0].JsonDocument -and ($JsonObfContainer.JsonDocumentPath -eq 'N/A'))
                {
                    # Encapsulate original JsonDocument value in single quotes and handle PowerShell-specific single quote escaping.
                    # If JsonDocument value is too long then change to $jsonDocument placeholder for more concise output formatting.
                    if ($JsonObfContainer.History[0].JsonDocument.Replace("'","''").Length -le $jsonDocumentDisplaySizeLimit)
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = " -JsonDocument '"                                          }
                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $JsonObfContainer.History[0].JsonDocument.Replace("'","''") }
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = "'"                                                         }
                        )
                    }
                    else
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';        Value = ' -JsonDocument ' }
                            [PSCustomObject] @{ ForegroundColor = 'DarkMagenta'; Value = '$jsonDocument'   }
                        )
                    }
                }

                # Set remaining CLI field values.
                $functionName   = [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = 'Invoke-SkyScalpel' }
                $argumentSyntax = [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = ' -Quiet -NoExit'   }

                # Output CLI syntax if set or obfuscation commands are present.
                if ($setSyntax -or $commandSyntax)
                {
                    $cliSyntaxToOutput = ([System.Array] $functionName + $setSyntax + $commandSyntax + $argumentSyntax).Where( { $_ } )

                    foreach ($line in $cliSyntaxToOutput)
                    {
                        Write-Host $line.Value -NoNewline -ForegroundColor $line.ForegroundColor
                    }
                    Write-Host ''
                }
                else
                {
                    Write-Host ''
                }
            }
            'ExecutionCommands' {
                if ($option.Value.Count -gt 1)
                {
                    Write-Host ''
                }

                # If JSON document is set but no obfuscation has been applied then skip displaying ExecutionCommands since it will only be setting the JsonDocument in a variable as a string.
                if (-not $JsonObfContainer.JsonDocument -or ($JsonObfContainer.Layer -eq 0))
                {
                    Write-Host ''

                    break
                }

                $counter = 0
                foreach ($executionCommand in $option.Value)
                {
                    $counter++

                    # If initial JSON document is too long then skip displaying its instantiation command for more concise output formatting.
                    if (($counter -eq 1) -and (($JsonObfContainer.History[0].JsonDocument).Replace("'","''").Length -gt $jsonDocumentDisplaySizeLimit))
                    {
                        continue
                    }

                    # Handle output formatting of newline when SHOW OPTIONS is run.
                    if ($counter -eq ($option.Value | Measure-Object).Count)
                    {
                        $noNewLine = $true
                    }
                    else
                    {
                        $noNewLine = $false
                    }

                    # Split out $jsonObfContainer and original -JsonDocument/-JsonDocumentPath value so they can be output in different color.
                    if ($option.Value.Count -gt 1)
                    {
                        Write-Host '    ' -NoNewline
                    }

                    # Prepend $executionCommand with prefix arguments for obfuscation commands (skipping first command which is just JSON document string variable instantiation).
                    if ($counter -gt 1)
                    {
                        $executionCommand = $requiredFunctionPrefixArgumentsToHideFromUI + $executionCommand
                    }

                    # Prepend $executionCommand with JSON document string variable instantiation syntax.
                    $executionCommand = '$jsonDocument = ' + $executionCommand

                    # Split and add additional highlighting for variable placeholders in execution command syntax values.
                    ($executionCommand -isplit '\$jsonDocument').Where( { $_ } ) | ForEach-Object {
                        $remainingCommand = $_

                        Write-Host '$jsonDocument' -NoNewline -ForegroundColor DarkMagenta

                        # Depending on JsonDocument and JsonDocumentPath length, substitute JSON document and JSON document path syntax for $jsonDocument and $jsonDocumentPath placeholder for more concise output formatting.
                        if ($remainingCommand -imatch "'$([regex]::Escape($JsonObfContainer.History[0].JsonDocument).Replace("'","''"))'")
                        {
                            # Split to extract potential encapsulating single quotes.
                            $remainingCommandSplit = $remainingCommand -isplit [regex]::Escape($Matches[0])

                            # Add encapsulating quotes to split command for proper coloring of output.
                            if (($Matches[0].Length - 2) -le $jsonDocumentDisplaySizeLimit)
                            {
                                # Add encapsulating single quote.
                                $remainingCommandSplit[0] = $remainingCommandSplit[0] + "'"
                                $remainingCommandSplit[1] = "'" + $remainingCommandSplit[1]
                            }

                            for ($i = 0; $i -lt (($remainingCommandSplit | Measure-Object).Count - 1); $i++)
                            {
                                Write-Host $remainingCommandSplit[$i] -NoNewline -ForegroundColor Cyan

                                # Encapsulate JsonDocument value in single quotes.
                                # If JsonDocument value is too long then change to $jsonDocument placeholder for more concise output formatting.
                                if (($Matches[0].Length - 2) -le $jsonDocumentDisplaySizeLimit)
                                {
                                    # Exclude encapsulating single quotes from $Matches[0] resultant from regex in -isplit command above.
                                    Write-Host $Matches[0].Substring(1,($Matches[0].Length - 2)) -NoNewline -ForegroundColor Magenta
                                }
                                else
                                {
                                    Write-Host '$jsonDocument' -NoNewline -ForegroundColor DarkMagenta
                                }
                            }

                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $remainingCommandSplit[$i]
                        }
                        elseif (($remainingCommand -match [regex]::Escape($JsonObfContainer.JsonDocumentPath)) -and ($JsonObfContainer.JsonDocumentPath -ne 'N/A'))
                        {
                            # Split to extract potential encapsulating single quotes.
                            if ($Matches[0].Length -le $jsonDocumentDisplaySizeLimit)
                            {
                                $remainingCommandSplit = $remainingCommand -isplit [regex]::Escape($Matches[0])
                            }
                            else
                            {
                                $remainingCommandSplit = $remainingCommand -isplit ("'$([regex]::Escape($Matches[0]))'")
                            }
                            for ($i = 0; $i -lt (($remainingCommandSplit | Measure-Object).Count - 1); $i++)
                            {
                                Write-Host $remainingCommandSplit[$i] -NoNewline -ForegroundColor Cyan

                                # If JsonDocumentPath value is too long then change to $jsonDocumentPath placeholder for more concise output formatting.
                                if ($Matches[0].Length -le $jsonDocumentDisplaySizeLimit)
                                {
                                    Write-Host $Matches[0] -NoNewline -ForegroundColor Magenta
                                }
                                else
                                {
                                    Write-Host '$jsonDocumentPath' -NoNewline -ForegroundColor DarkMagenta
                                }
                            }

                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $remainingCommandSplit[$i]
                        }
                        else
                        {
                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $_
                        }

                        Write-Host $remainingCommand -NoNewline -ForegroundColor Cyan
                    }
                    Write-Host '' -NoNewline:$noNewLine
                }
                Write-Host ''

                # Output one-liner version of ExecutionCommands below PowerShell-themed comment.
                Write-Host '    # One-liner ExecutionCommand' -ForegroundColor DarkGreen
                Write-Host '    ' -NoNewline

                $counter = 0
                foreach ($executionCommand in $option.Value)
                {
                    $counter++

                    # If initial JSON document is too long then skip displaying its instantiation command for more concise output formatting.
                    if ($counter -eq 1)
                    {
                        if ($executionCommand.Replace("'","''").Length -le $jsonDocumentDisplaySizeLimit)
                        {
                            # Output color-coded JSON document variable instantiation.
                            Write-Host "'" -NoNewline -ForegroundColor Cyan
                            Write-Host $executionCommand.Trim("'").Replace("'","''") -NoNewline -ForegroundColor Magenta
                            Write-Host "'" -NoNewline -ForegroundColor Cyan
                        }
                        else
                        {
                            # Output JSON document variable placeholder.
                            Write-Host '$jsonDocument' -NoNewline -ForegroundColor DarkMagenta
                        }
                    }
                    else
                    {
                        # Output next command in one-liner pipeline syntax.
                        Write-Host " | $executionCommand" -NoNewline -ForegroundColor Cyan
                    }
                }
                Write-Host ''

            }
            'ObfuscatedJsonDocument' {
                # Output ObfuscatedJsonDocument (unless it is not yet defined).
                if ($option.Value)
                {
                    # Drop to next line if multiple values are present for more aligned output formatting.
                    if ($option.Value -match "`n")
                    {
                        Write-Host ''
                    }

                    Out-JsonObject -InputObject $JsonObfContainer.JsonDocumentTokenized -SkipModificationHighlighting -Format raw
                }
                else
                {
                    Write-Host ''
                }
            }
            'DetectionScore' {
                Write-Host $option.Value -ForegroundColor ($option.Value -gt 0.0 ? 'Red' : 'Cyan')
            }
            'DetectionCount' {
                Write-Host $option.Value -ForegroundColor ($option.Value -gt 0.0 ? 'Red' : 'Cyan')
            }
            default {
                # If multiple values then output as PowerShell array syntax.
                if ($option.Value.Count -gt 1)
                {
                    Write-Host ($option.Value -join ',') -ForegroundColor Magenta
                }
                else
                {
                    Write-Host $option.Value -ForegroundColor Magenta
                }
            }
        }
    }
}


function Show-HelpMenu
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-HelpMenu
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-HelpMenu displays color-coded help menu for Invoke-SkyScalpel function.

.PARAMETER InputOptionMenu

Specifies object containing list of available menu option values and descriptions to display.

.EXAMPLE

C:\PS> Show-HelpMenu

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]
        $InputOptionMenu
    )

    # Show Help Menu.
    Write-Host "`n`nHELP MENU" -NoNewline -ForegroundColor Cyan
    Write-Host ' :: Available' -NoNewline
    Write-Host ' options' -NoNewline -ForegroundColor Yellow
    Write-Host " shown below:`n"
    foreach ($inputOption in $InputOptionMenu.PSObject.Properties.Where( { $_.Value.Option -and $_.Value.Description } ).Value)
    {
        # Add additional coloring to string encapsulated by <> if it exists in $inputOption.Description.
        if ($inputOption.Description -cmatch '<.*>')
        {
            Write-Host "`t" -NoNewline

            $remainingDescription = $inputOption.Description
            while ($remainingDescription -cmatch '<[^>]+>')
            {
                $firstPart  = $remainingDescription.Substring(0,$remainingDescription.IndexOf($Matches[0]))
                $middlePart = $remainingDescription.Substring(($firstPart.Length + 1),($Matches[0].Length - 2))
                Write-Host $firstPart -NoNewline
                Write-Host $middlePart -NoNewline -ForegroundColor Cyan

                # Set $remainingDescription as remaining substring so additional highlighting (if present) can occur in current while loop.
                $remainingIndex = $firstPart.Length + $middlePart.Length + 2
                if ($remainingIndex -gt $remainingDescription.Length)
                {
                    $remainingDescription = $null
                }
                else
                {
                    $remainingDescription = $remainingDescription.Substring($remainingIndex)
                }
            }

            # Output remaining $remainingDescription.
            if ($remainingDescription)
            {
            Write-Host $remainingDescription -NoNewline
            }
        }
        else
        {
            Write-Host "`t$($inputOption.Description)" -NoNewline
        }

        # Output yellow-colored options corresponding to above description output.
        for ($i = 0; $i -lt $inputOption.Option.Count - 1; $i++)
        {
            Write-Host $inputOption.Option[$i].ToUpper() -NoNewline -ForegroundColor Yellow
            Write-Host ', ' -NoNewline
        }
        Write-Host $inputOption.Option[$i].ToUpper() -ForegroundColor Yellow
    }
}


function Show-Tutorial
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-Tutorial
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Show-Tutorial displays color-coded tutorial for Invoke-SkyScalpel function.

.EXAMPLE

C:\PS> Show-Tutorial

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    Write-Host "`n`nTUTORIAL"                                                                     -NoNewline -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to get your obfuscation on:"

    Write-Host "`n1) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Load a JSON document (SET JSONDOCUMENT) or a JSON document file path/URL (SET JSONDOCUMENTPATH)."
    Write-Host '   SET JSONDOCUMENT {"country":"Kosovë","city":"Gjakova"}'                                   -ForegroundColor Green

    Write-Host "`n2) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in"                  -NoNewline
    Write-Host " YELLOW"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN"                                                                         -NoNewline -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " BACK"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "CD .."                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host " to go to previous menu &"                                                        -NoNewline
    Write-Host " HOME"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "MAIN"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter"                                              -NoNewline
    Write-Host " OBFUSCATE"                                                                       -NoNewline -ForegroundColor Yellow
    Write-Host ","                                                                                -NoNewline
    Write-Host " JSON"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host ","                                                                                -NoNewline
    Write-Host " WHITESPACE"                                                                      -NoNewline -ForegroundColor Yellow
    Write-Host " & then"                                                                          -NoNewline
    Write-Host " 4"                                                                               -NoNewline -ForegroundColor Green
    Write-Host " to apply Whitespace obfuscation."

    Write-Host "`n3)"                                                                             -NoNewline -ForegroundColor Cyan
    Write-Host " Regex & randomization shortcuts can be used in menu traversal.`n   E.g. Enter"   -NoNewline
    Write-Host " HOME\OBF*\JSON\(WHITESPACE|UNICODE)\*\"                                          -NoNewline -ForegroundColor Yellow
    Write-Host "3"                                                                                -NoNewline -ForegroundColor Green
    Write-Host " for a mixture of regex & simple wildcards."
    Write-Host "   E.g. Enter "                                                                   -NoNewline
    Write-Host "**"                                                                               -NoNewline -ForegroundColor Green
    Write-Host ", "                                                                               -NoNewline
    Write-Host "***"                                                                              -NoNewline -ForegroundColor Green
    Write-Host " or "                                                                             -NoNewline
    Write-Host "****"                                                                             -NoNewline -ForegroundColor Green
    Write-Host " to randomly apply one, some or all downstream menu options."

    Write-Host "`n4) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " DETECT"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "FIND-EVIL"                                                                        -NoNewline -ForegroundColor Yellow
    Write-Host " to evaluate all detection rules against obfuscated JSON document."

    Write-Host "`n5) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " COPY"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "CLIP"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to copy obfuscated JSON document out to your clipboard."
    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " OUT"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to write obfuscated JSON document out to disk."

    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " EXPORT"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host " to write obfuscation container (with all obfuscation layers) out to disk."

    Write-Host "`n6) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " RESET"                                                                           -NoNewline -ForegroundColor Yellow
    Write-Host " to remove all obfuscation & start over.`n   Enter"                               -NoNewline
    Write-Host " UNDO"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host " to undo last obfuscation layer.`n   Enter"                                       -NoNewline
    Write-Host " HELP"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "?"                                                                                -NoNewline -ForegroundColor Yellow
    Write-Host " for help menu."

    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`""                 -NoNewline -ForegroundColor Cyan
    Write-Host " :)"                                                                                         -ForegroundColor Green
}


function Split-Command
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Split-Command
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Split-Command splits input command or array of commands joined by commas or slashes as supported by the Invoke-SkyScalpel function.

.PARAMETER Command

Specifies command or array of commands joined by commas or slashes to split for input into Invoke-SkyScalpel function.

.EXAMPLE

C:\PS> @('Home\Obfuscate\JSON\Unicode\4,back,Whitespace\3,3','Home\Deobfuscate\AWSPolicy\Wildcard*\3') | Split-Command

Home
Obfuscate
JSON
Unicode
4
back
Whitespace
3
3
Home
Deobfuscate
AWSPolicy
Wildcard*
3

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $Command
    )

    begin
    {

    }

    process
    {
        # Iterate over each input command.
        foreach ($curCommand in $Command)
        {
            # Extract potential concatenated commands while applying special logic if 'SET JSONDOCUMENT'
            # scenario is present to avoid potentially setting an incomplete value.
            $firstSplit = $true
            $commandSplit = @($curCommand -isplit ',\s*SET ' | ForEach-Object {
                if ($firstSplit)
                {
                    $firstSplit = $false
                    $_.TrimStart()
                }
                else
                {
                    "SET $($_.TrimStart())"
                }
            })

            # Split on any commas to extract potential additional non-SET concatenated commands.
            # Additionally, for any non-SET command(s), split on slashes to further extract subcommands. E.g. HOME\OBFUSCATE\JSON\UNICODE
            @(for ($i = 0; $i -lt $commandSplit.Count; $i++)
            {
                # For 'SET JSONDOCUMENT' scenario where commas can legitimately be found in the value being set then treat entire user input as the value.
                if ($commandSplit[$i] -imatch '^set\s+jsondocument\s+.*,')
                {
                    # Return remainder of command as single unit since JSONDOCUMENT is a settable property that can legimately 
                    # have commas in its value, so splitting on commas would potentially cause incomplete values to be set.
                    $joinedCommandSplit = $commandSplit[$i..$commandSplit.Count] -join ','

                    # Return joined command.
                    $joinedCommandSplit

                    # Break out of current for loop since all remaining split commands were returned above.
                    break
                }
                else
                {
                    # Split on any remaining commas to extract potential additional non-SET concatenated commands.
                    $commandSplit[$i].Split(',').TrimStart().Where( { $_ } ) | ForEach-Object {
                        # Additionally, for any non-SET/OUT/EXPORT command(s) then split on slashes to further extract subcommands. E.g. HOME\OBFUSCATE\JSON\UNICODE
                        if ($_ -notmatch '^\s*(set|out|export) ')
                        {
                            # Do not change below since $_.Split('/\') does not behave as expected in PowerShell Core
                            $_ -csplit '[/\\]'
                        }
                        else
                        {
                            $_
                        }
                    }
                }
            })
        }
    }

    end
    {

    }
}


function Show-AsciiArt
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Show-AsciiArt
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-AsciiArt displays static ASCII art title banner and optional animated ASCII art introduction for Invoke-SkyScalpel function.

.PARAMETER Animated

(Optional) Specifies that animated ASCII art introduction be displayed before displaying default static ASCII art title banner.

.EXAMPLE

C:\PS> Show-AsciiArt

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Animated
    )

    # Create ASCII art title banner.
    $padding = '    '
    $invokeSkyScalpelAscii = @'
     ,gg,                                           __      _______   
    i8""8i    ,dPYb,                               /**\___,o_/__/___| 
    `8,,8'    IP'`Yb                               |_PERMISO/P0/LABS]>
     `88'     I8  8I                           _,d88 '\-===/==/===='| 
     dP"8,    I8  8bgg,                    _,d8P                "o    
    dP' `8a   I8 dP" "8  gg     gg      ,d8                           
   dP'   `Yb  I8d8bggP"  I8     8I   ,d8                              
_ ,dP'     I8 I8P' "Yb,  I8,   ,8I ,d8                                
"888,,____,dP,d8    `Yb,,d8b, ,d8Id8                                  
a8P"Y88888P" 88P      Y8P""Y88P"888                                   
                             ,d8I'                                    
     ,gg,                  ,dP'8I                                     
    i8""8i                ,8"  8I ,dPYb,                       ,dPYb, 
    `8,,8'                I8   8I IP'`Yb                       IP'`Yb 
     `88'                 `8, ,8I I8  8I                       I8  8I 
     dP"8,                 `Y8P"  I8  8'                       I8  8' 
    dP' `8a    ,gggg,    ,gggg,gg I8 dP   gg,gggg,     ,ggg,   I8 dP  
   dP'   `Yb  dP"  "Yb  dP"  "Y8I I8dP    I8P"  "Yb   i8" "8i  I8dP   
_ ,dP'     I8 i8'       i8'    ,8I I8P    I8' O  ,8i  I8, ,8I  I8P    
"888,,____,dP,d8,_    _,d8,   ,d8b,d8b,_ ,I8 _  ,d8'  `YbadP' ,d8b,_  
a8P"Y88888P" P""Y8888PPP"Y8888P"`Y8P'"Y88PI8 YY88888P888P"Y8888P'"Y88 
                                          I8                          
                                          I8  ___ __ .  . .  __  __   
                                          I8 |__ |__)|\/| | /__`/  \  
                                          I8 |___|  \|  | | .__/\__/  
'@.Split("`n").ForEach( { $padding + $_ } )

    # Define output foreground colors for each element when outputting ASCII art title banner below.
    $colorObj = [PSCustomObject] @{
        Primary          = [System.ConsoleColor]::DarkMagenta
        PermisoPrimary   = [System.ConsoleColor]::Cyan
        PermisoSecondary = [System.ConsoleColor]::Yellow
        Plane            = [System.ConsoleColor]::Blue
    }

    # Create array of index objects for color-coding above ASCII art title banner.
    $indexObj = [PSCustomObject] @{
        0 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 51; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 51; Length = 18; ForegroundColor = $colorObj.Plane            }
        )
        1 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 51; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 51; Length = 18; ForegroundColor = $colorObj.Plane            }
        )
        2 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 51; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 51; Length =  2; ForegroundColor = $colorObj.Plane            }
            [PSCustomObject] @{ IndexStart = 53; Length =  7; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 60; Length =  1; ForegroundColor = $colorObj.Plane            }
            [PSCustomObject] @{ IndexStart = 61; Length =  2; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 63; Length =  1; ForegroundColor = $colorObj.Plane            }
            [PSCustomObject] @{ IndexStart = 64; Length =  4; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 68; Length =  3; ForegroundColor = $colorObj.Plane            }
        )
        3 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 53; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 53; Length = 16; ForegroundColor = $colorObj.Plane            }
        )
        4 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 64; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 64; Length =  5; ForegroundColor = $colorObj.Plane            }
        )
        5 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        6 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        7 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        8 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        9 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        10 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        11 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        12 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        13 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        14 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        15 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 69; ForegroundColor = $colorObj.Primary          }
        )
        16 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length =  8; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 50; Length = 19; ForegroundColor = $colorObj.Primary          }
        )
        17 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length =  9; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 51; Length = 18; ForegroundColor = $colorObj.Primary          }
        )
        18 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length =  3; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 45; Length =  4; ForegroundColor = $colorObj.PermisoSecondary }
            [PSCustomObject] @{ IndexStart = 49; Length =  3; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 52; Length = 17; ForegroundColor = $colorObj.Primary          }
        )
        19 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length = 10; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 52; Length = 17; ForegroundColor = $colorObj.Primary          }
        )
        20 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length =  7; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 49; Length = 20; ForegroundColor = $colorObj.Primary          }
        )
        21 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length =  9; ForegroundColor = $colorObj.PermisoPrimary   }
            [PSCustomObject] @{ IndexStart = 51; Length = 18; ForegroundColor = $colorObj.Primary          }
        )
        22 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length = 27; ForegroundColor = $colorObj.PermisoPrimary   }
        )
        23 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length = 27; ForegroundColor = $colorObj.PermisoPrimary   }
        )
        24 = @(
            [PSCustomObject] @{ IndexStart =  0; Length = 42; ForegroundColor = $colorObj.Primary          }
            [PSCustomObject] @{ IndexStart = 42; Length = 27; ForegroundColor = $colorObj.PermisoPrimary   }
        )
    }

    # Animated ASCII art to display if user input -Animated switch parameter is defined (e.g. only run during interactive Invoke-SkyScalpel function invocation).
    if ($Animated.IsPresent)
    {
        $arrowAscii  = @()
        $arrowAscii += '  |  '
        $arrowAscii += '  |  '
        $arrowAscii += ' \ / '
        $arrowAscii += '  V  '

        # Show actual obfuscation example (generated with this tool) in reverse.
        $policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]}'
        $policyObfLayer1 = $policy | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 40 -RandomLength 1 -Format Plaintext -Type Replace -TrackModification -Target JsonToken
        $policyObfLayer2 = $policyObfLayer1 | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 40 -Format Plaintext -TrackModification -Target JsonToken
        $policyObfLayer3 = $policyObfLayer2 | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 40 -TrackModification -Target JsonToken
        $policyObfLayer4 = $policyObfLayer3 | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength @(3..15) -TrackModification -Target JsonToken

        $policy | Out-JsonObject
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        $policyObfLayer1 | Out-JsonObject
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line -NoNewline
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        $policyObfLayer2 | Out-JsonObject
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line -NoNewline
            Write-Host $line -NoNewline
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        $policyObfLayer3 | Out-JsonObject
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line -NoNewline
            Write-Host $line -NoNewline
            Write-Host $line -NoNewline
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        $policyObfLayer4 | Out-JsonObject
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        # Write out below string in interactive format.
        Start-Sleep -Milliseconds 100
        foreach ($char in [System.Char[]] 'Invoke-SkyScalpel')
        {
            Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
            Write-Host $char -NoNewline -ForegroundColor Green
        }

        Start-Sleep -Milliseconds 900
        Write-Host ""
        Start-Sleep -Milliseconds 300
        Write-Host
    }

    # Display ASCII art title banner based on previously defined array of index objects for color-coding.
    # Iterate over each line's array of index objects.
    foreach ($curLineIndex in $indexObj.PSObject.Properties.Name)
    {
        Write-Host $padding -NoNewline

        # Iterate over each substring index object for current line.
        foreach ($curLineIndexObj in $indexObj.$curLineIndex)
        {
            $optionalForegroundColor = $curLineIndexObj.ForegroundColor ? @{ ForegroundColor = $curLineIndexObj.ForegroundColor } : @{ }
            Write-Host $invokeSkyScalpelAscii[$curLineIndex].Substring(($padding.Length + $curLineIndexObj.IndexStart),$curLineIndexObj.Length) -NoNewline @optionalForegroundColor
        }

        # Output newline after outputting all substrings for current line above.
        Write-Host ''
    }
}


function New-ObfuscationContainer
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: New-ObfuscationContainer
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonObject
Optional Dependencies: None

.DESCRIPTION

New-ObfuscationContainer creates obfuscation container to store history of JSON document obfuscation layers.

.PARAMETER JsonDocument

Specifies initial JSON document to which future obfuscation layers can be applied.

.PARAMETER JsonDocumentPath

Specifies path to file containing initial JSON document to which future obfuscation layers can be applied.

.EXAMPLE

C:\PS> New-ObfuscationContainer -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}'

Layer                         : 0
JsonDocument                  : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances",
                                "iam:PassRole"],"Resource":"*"}}
JsonDocumentTokenized         : {Depth: 0, Length: 1, Format: , Type: BeginObject, SubType: , Content: {, 
                                ContentDecoded: {, Path.ContentDecoded: , Path.Content: , Depth: 1, Length: 9, 
                                Format: String, Type: Name, SubType: ObjectMember, Content: "Version", 
                                ContentDecoded: "Version", Path.ContentDecoded: Version, Path.Content: Version, 
                                Depth: 1, Length: 1, Format: , Type: NameSeparator, SubType: , Content: :, 
                                ContentDecoded: :, Path.ContentDecoded: Version, Path.Content: Version, Depth: 1, 
                                Length: 12, Format: String, Type: Value, SubType: ObjectMember, Content: 
                                "2012-10-17", ContentDecoded: "2012-10-17", Path.ContentDecoded: Version, 
                                Path.Content: Version…}
JsonDocumentSize              : 115
JsonDocumentTokenizedSize     : 25
JsonDocumentValueCount        : 5
JsonDocumentDepth             : 4
JsonDocumentMD5               : ADD41BA60AF2AC95660F994280445566
JsonDocumentOrig              : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances",
                                "iam:PassRole"],"Resource":"*"}}
JsonDocumentOrigSize          : 115
JsonDocumentOrigTokenizedSize : 25
JsonDocumentOrigCount         : 5
JsonDocumentOrigDepth         : 4
JsonDocumentOrigMD5           : ADD41BA60AF2AC95660F994280445566
JsonDocumentPath              : 
History                       : {@{Layer=0; JsonDocument={"Version":"2012-10-17","Statement":{"Effect":"Allow","Act
                                ion":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}; 
                                JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; JsonDocumentSize=115; 
                                JsonDocumentTokenizedSize=25; JsonDocumentValueCount=5; JsonDocumentDepth=4; 
                                JsonDocumentMD5=ADD41BA60AF2AC95660F994280445566; JsonDocumentOrig={"Version":"2012
                                -10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],
                                "Resource":"*"}}; JsonDocumentOrigSize=115; JsonDocumentOrigTokenizedSize=25; 
                                JsonDocumentOrigCount=5; JsonDocumentOrigDepth=4; 
                                JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; 
                                Function=New-ObfuscationContainer; CommandLineSyntax='{"Version":"2012-10-17","Stat
                                ement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*
                                "}}'; CliSyntax=System.Object[]}}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'JsonDocument')]
        [System.String[]]
        $JsonDocument,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'JsonDocumentPath')]
        [System.IO.FileInfo[]]
        $JsonDocumentPath
    )

    begin
    {
        # Array that will house single or multiple input JSON documents.
        $jsonDocumentArr = @()
    }

    process
    {
        # Handle various input formats to produce the same data format in the $jsonDocumentArr array.
        switch ($PSCmdlet.ParameterSetName)
        {
            'JsonDocumentPath' {
                # Read in file path(s) as a string and add to $jsonDocumentArr array.
                foreach ($curPath in $executionContext.SessionState.Path.GetResolvedProviderPathFromProviderPath($JsonDocumentPath, 'FileSystem'))
                {
                    # Remove single trailing newline when reading text from file.
                    $jsonDocumentArr += ([System.IO.File]::ReadAllText($curPath) -replace "`r`n","`n" -replace "`n$",'')
                }
            }
            'JsonDocument' {
                # Cast input JSON document(s) as a string and add to $jsonDocumentArr array.
                foreach ($curJsonDocument in $JsonDocument)
                {
                    $jsonDocumentArr += [System.String] $curJsonDocument
                }
            }
        }
    }

    end
    {
        # Iterate over each JSON document added to $jsonDocumentArr in process pipeline above.
        foreach ($curJsonDocument in $jsonDocumentArr)
        {
            # Handle if initial JSON document should be null for creating empty obfuscation container.
            if ($curJsonDocument -eq ' ')
            {
                # PowerShell function's required input parameter does not accept $null or empty string, so we use single whitespace instead as input then change back to empty string.
                $curJsonDocument = ''
            }

            # Perform initial tokenization and calculate JSON document Value count and depth.
            if ($curJsonDocument)
            {
                # Convert initial JSON document string into tokenized JSON document.
                $curJsonDocumentTokenized = ConvertTo-JsonObject -InputObject $curJsonDocument -Target JsonTokenEnriched

                # Calculate JSON document Value count.
                $curJsonDocumentValueCount = $curJsonDocumentTokenized.Where( { ($_ -is [SkyScalpel.JsonToken]) -and ($_.Type -eq [SkyScalpel.JsonTokenType]::Value) } ).Count

                # Calculate JSON document depth, adding 1 since SkyScalpel JSON document depth starts with 0.
                $curJsonDocumentDepth = ($curJsonDocumentTokenized.Depth | Sort-Object -Unique | Select-Object -Last 1) + 1
            }
            else
            {
                $curJsonDocumentTokenized = @()
                $curJsonDocumentValueCount = 0
                $curJsonDocumentDepth = 0
            }

            # Calculate MD5 hash of JSON document.
            $curJsonDocumentMD5 = [System.String] (Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::UTF8.GetBytes($curJsonDocument))) -Algorithm MD5).Hash

            # Return obfuscation container to house each step of obfuscation history.
            [PSCustomObject] @{
                # Values for current layer.
                Layer                         = [System.Int16]  0
                JsonDocument                  = [System.String] $curJsonDocument
                JsonDocumentTokenized         = [SkyScalpel.JsonTokenEnriched[]] $curJsonDocumentTokenized
                JsonDocumentSize              = [System.Int64]  $curJsonDocument.Length
                JsonDocumentTokenizedSize     = [System.Int64]  $curJsonDocumentTokenized.Count
                JsonDocumentValueCount        = [System.Int64]  $curJsonDocumentValueCount
                JsonDocumentDepth             = [System.Int64]  $curJsonDocumentDepth
                JsonDocumentMD5               = [System.String] $curJsonDocumentMD5

                # Values for original layer.
                JsonDocumentOrig              = [System.String] $curJsonDocument
                JsonDocumentOrigSize          = [System.Int64]  $curJsonDocument.Length
                JsonDocumentOrigTokenizedSize = [System.Int64]  $curJsonDocumentTokenized.Count
                JsonDocumentOrigCount         = [System.Int64]  $curJsonDocumentValueCount
                JsonDocumentOrigDepth         = [System.Int64]  $curJsonDocumentDepth
                JsonDocumentOrigMD5           = [System.String] $curJsonDocumentMD5

                # Set JsonDocumentPath as placeholder property for Invoke-SkyScalpel to update if SET JSONDOCUMENTPATH is used instead of SET JSONDOCUMENT.
                JsonDocumentPath              = [System.String]   $null

                # History property is an array that will store all previous obfuscation layers as they are added or removed via Add-ObfuscationLayer and Remove-ObfuscationLayer, respectively.
                History = @(
                    [PSCustomObject] @{
                        # Values for current layer.
                        Layer                         = [System.Int16]  0
                        JsonDocument                  = [System.String] $curJsonDocument
                        JsonDocumentTokenized         = [SkyScalpel.JsonTokenEnriched[]] $curJsonDocumentTokenized
                        JsonDocumentSize              = [System.Int64]  $curJsonDocument.Length
                        JsonDocumentTokenizedSize     = [System.Int64]  $curJsonDocumentTokenized.Count
                        JsonDocumentValueCount        = [System.Int64]  $curJsonDocumentValueCount
                        JsonDocumentDepth             = [System.Int64]  $curJsonDocumentDepth
                        JsonDocumentMD5               = [System.String] $curJsonDocumentMD5

                        # Values for original layer.
                        JsonDocumentOrig              = [System.String] $curJsonDocument
                        JsonDocumentOrigSize          = [System.Int64]  $curJsonDocument.Length
                        JsonDocumentOrigTokenizedSize = [System.Int64]  $curJsonDocumentTokenized.Count
                        JsonDocumentOrigCount         = [System.Int64]  $curJsonDocumentValueCount
                        JsonDocumentOrigDepth         = [System.Int64]  $curJsonDocumentDepth
                        JsonDocumentOrigMD5           = [System.String] $curJsonDocumentMD5

                        # Below field only added for each item in History array property and not stored in overall main properties.
                        Function = [System.String] $MyInvocation.MyCommand.Name

                        # Below two properties are only used when function is called from Invoke-SkyScalpel for interactive display purposes.
                        # CommandLineSyntax is assembled in this function, but CliSyntax must be assembled by calling Invoke-SkyScalpel function.
                        CommandLineSyntax = [System.String] "'$($curJsonDocument.Replace("'","''"))'"
                        CliSyntax         = [System.Array]  @()
                    }
                )
            }
        }
    }
}


function Add-ObfuscationLayer
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-ObfuscationLayer
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Add-ObfuscationLayer adds input JSON document as additional obfuscation layer into input obfuscation container.

.PARAMETER ObfuscationContainer

Specifies obfuscation container in which to add input JSON document as additional obfuscation layer.

.PARAMETER JsonDocumentTokenized

Specifies JSON document to add as additional obfuscation layer into input obfuscation container.

.EXAMPLE

C:\PS> $obfContainer = New-ObfuscationContainer -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}'
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -JsonDocumentTokenized ('{"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINstaNces","IA\u004D:pasSroLE"],"Re\u0073o\u0075rce":"*"}}' | ConvertTo-JsonObject -Target JsonTokenEnriched)
C:\PS> $obfContainer

Layer                         : 1
JsonDocument                  : {"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2
                                :RunINstaNces","IA\u004D:pasSroLE"],"Re\u0073o\u0075rce":"*"}}
JsonDocumentTokenized         : {Depth: 0, Length: 1, Format: , Type: BeginObject, SubType: , Content: {, 
                                ContentDecoded: {, Path.ContentDecoded: , Path.Content: , Depth: 1, Length: 9, 
                                Format: String, Type: Name, SubType: ObjectMember, Content: "Version", 
                                ContentDecoded: "Version", Path.ContentDecoded: Version, Path.Content: Version, 
                                Depth: 1, Length: 1, Format: , Type: NameSeparator, SubType: , Content: :, 
                                ContentDecoded: :, Path.ContentDecoded: Version, Path.Content: Version, Depth: 1, 
                                Length: 12, Format: String, Type: Value, SubType: ObjectMember, Content: 
                                "2012-10-17", ContentDecoded: "2012-10-17", Path.ContentDecoded: Version, 
                                Path.Content: Version…}
JsonDocumentSize              : 145
JsonDocumentTokenizedSize     : 25
JsonDocumentValueCount        : 5
JsonDocumentDepth             : 4
JsonDocumentMD5               : B640828D53C6D2C8C098CCC63A25EB2F
JsonDocumentOrig              : {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances",
                                "iam:PassRole"],"Resource":"*"}}
JsonDocumentOrigSize          : 115
JsonDocumentOrigTokenizedSize : 25
JsonDocumentOrigCount         : 5
JsonDocumentOrigDepth         : 4
JsonDocumentOrigMD5           : ADD41BA60AF2AC95660F994280445566
JsonDocumentPath              : 
History                       : {@{Layer=0; JsonDocument={"Version":"2012-10-17","Statement":{"Effect":"Allow","Act
                                ion":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}; 
                                JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; JsonDocumentSize=115; 
                                JsonDocumentTokenizedSize=25; JsonDocumentValueCount=5; JsonDocumentDepth=4; 
                                JsonDocumentMD5=ADD41BA60AF2AC95660F994280445566; JsonDocumentOrig={"Version":"2012
                                -10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],
                                "Resource":"*"}}; JsonDocumentOrigSize=115; JsonDocumentOrigTokenizedSize=25; 
                                JsonDocumentOrigCount=5; JsonDocumentOrigDepth=4; 
                                JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; 
                                Function=New-ObfuscationContainer; CommandLineSyntax='{"Version":"2012-10-17","Stat
                                ement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*
                                "}}'; CliSyntax=System.Object[]}, @{Layer=1; JsonDocument={"Version":"2012-10-17","
                                Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINstaNces","IA\u004D:
                                pasSroLE"],"Re\u0073o\u0075rce":"*"}}; 
                                JsonDocumentTokenized=SkyScalpel.JsonTokenEnriched[]; JsonDocumentSize=145; 
                                JsonDocumentTokenizedSize=25; JsonDocumentValueCount=5; JsonDocumentDepth=4; 
                                JsonDocumentMD5=B640828D53C6D2C8C098CCC63A25EB2F; JsonDocumentOrig={"Version":"2012
                                -10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],
                                "Resource":"*"}}; JsonDocumentOrigSize=115; JsonDocumentOrigTokenizedSize=25; 
                                JsonDocumentOrigCount=5; JsonDocumentOrigDepth=4; 
                                JsonDocumentOrigMD5=ADD41BA60AF2AC95660F994280445566; Function=; 
                                CliSyntax=System.Object[]; CommandLineSyntax=}}

.EXAMPLE

C:\PS> $obfContainer = $obfContainer = New-ObfuscationContainer -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}'
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -JsonDocumentTokenized ('{"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINstaNces","IA\u004D:pasSroLE"],"Re\u0073o\u0075rce":"*"}}' | ConvertTo-JsonObject -Target JsonTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -JsonDocumentTokenized ('{  "Version" :"20\u0031\u0032-1\u0030-17"  ,  "Statement":{   "Ef\u0066ect":"\u0041l\u006Co\u0077",  "Action":   ["Ec2:RunINstaNce***s" , "IA\u004D:pas??oLE"],  "Re\u0073o\u0075rce" : "\u002A"  }  }' | ConvertTo-JsonObject -Target JsonTokenEnriched)
C:\PS> $obfContainer.History | Select-Object Layer,JsonDocumentSize,JsonDocument

Layer JsonDocumentSize JsonDocument
----- ---------------- ------------
    0              115 {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:Pas…
    1              145 {"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINst…
    2              198 {  "Version" :"20\u0031\u0032-1\u0030-17"  ,  "Statement":{   "Ef\u0066ect":"\u0041l\u006Co…

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $ObfuscationContainer,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [SkyScalpel.JsonTokenEnriched[]]
        $JsonDocumentTokenized
    )

    begin
    {

    }

    process
    {
        # Iterate over each input -ObfuscationContainer object.
        foreach ($curObfuscationContainer in $ObfuscationContainer)
        {
            # Make copy of $curObfuscationContainer PSCustomObject so changes in this function do not affect input -ObfuscationContainer object outside this function.
            $curObfuscationContainer = $curObfuscationContainer.PSObject.Copy()

            # Calculate JSON document Value count.
            $curJsonDocumentValueCount = $JsonDocumentTokenized.Where( { ($_ -is [SkyScalpel.JsonToken]) -and ($_.Type -eq [SkyScalpel.JsonTokenType]::Value) } ).Count

            # Calculate JSON document depth, adding 1 since SkyScalpel JSON document depth starts with 0.
            $curJsonDocumentDepth = ($JsonDocumentTokenized.Depth | Sort-Object -Unique | Select-Object -Last 1) + 1

            # Update $curObfuscationContainer with new values before returning.
            $curObfuscationContainer.Layer                     = [System.Int16]  ($curObfuscationContainer.Layer + 1)
            $curObfuscationContainer.JsonDocument              = [System.String] -join$JsonDocumentTokenized.Content
            $curObfuscationContainer.JsonDocumentTokenized     = [SkyScalpel.JsonTokenEnriched[]] $JsonDocumentTokenized
            $curObfuscationContainer.JsonDocumentSize          = [System.Int64]  $curObfuscationContainer.JsonDocument.Length
            $curObfuscationContainer.JsonDocumentTokenizedSize = [System.Int64]  $curObfuscationContainer.JsonDocumentTokenized.Count
            $curObfuscationContainer.JsonDocumentValueCount    = [System.Int16]  $curJsonDocumentValueCount
            $curObfuscationContainer.JsonDocumentDepth         = [System.Int16]  $curJsonDocumentDepth
            $curObfuscationContainer.JsonDocumentMD5           = [System.String] (Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::UTF8.GetBytes($curObfuscationContainer.JsonDocument))) -Algorithm MD5).Hash

            # Set History property to empty array if it does not exist.
            if (-not $curObfuscationContainer.History)
            {
                $curObfuscationContainer.History = @()
            }

            # Add updated current obfuscation layer to History property array.
            $curObfuscationContainer.History += [PSCustomObject] @{
                # Values for current layer.
                Layer                         = [System.Int16]  $curObfuscationContainer.Layer
                JsonDocument                  = [System.String] $curObfuscationContainer.JsonDocument
                JsonDocumentTokenized         = [SkyScalpel.JsonTokenEnriched[]] $curObfuscationContainer.JsonDocumentTokenized
                JsonDocumentSize              = [System.Int64]  $curObfuscationContainer.JsonDocumentSize
                JsonDocumentTokenizedSize     = [System.Int64]  $curObfuscationContainer.JsonDocumentTokenizedSize
                JsonDocumentValueCount        = [System.Int64]  $curObfuscationContainer.JsonDocumentValueCount
                JsonDocumentDepth             = [System.Int64]  $curObfuscationContainer.JsonDocumentDepth
                JsonDocumentMD5               = [System.String] $curObfuscationContainer.JsonDocumentMD5

                # Values for original layer.
                JsonDocumentOrig              = [System.String] $curObfuscationContainer.JsonDocumentOrig
                JsonDocumentOrigSize          = [System.Int64]  $curObfuscationContainer.JsonDocumentOrigSize
                JsonDocumentOrigTokenizedSize = [System.Int64]  $curObfuscationContainer.JsonDocumentOrigTokenizedSize
                JsonDocumentOrigCount         = [System.Int64]  $curObfuscationContainer.JsonDocumentOrigCount
                JsonDocumentOrigDepth         = [System.Int64]  $curObfuscationContainer.JsonDocumentOrigDepth
                JsonDocumentOrigMD5           = [System.String] $curObfuscationContainer.JsonDocumentOrigMD5

                # Fields below only added for each item in History array property and not stored in overall main properties above outside History property entries.
                # Below three properties are only used when function is called from Invoke-SkyScalpel for interactive display purposes.
                Function          = [System.String] ''
                CliSyntax         = [System.Array]  @()
                CommandLineSyntax = [System.String] ''
            }

            # Return current updated obfuscation container object.
            $curObfuscationContainer
        }
    }

    end
    {

    }
}


function Remove-ObfuscationLayer
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Remove-ObfuscationLayer
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Remove-ObfuscationLayer removes last JSON document obfuscation layer from input obfuscation container.

.PARAMETER ObfuscationContainer

Specifies obfuscation container from which to remove last JSON document obfuscation layer (if it exists).

.EXAMPLE

C:\PS> $obfContainer = $obfContainer = New-ObfuscationContainer -JsonDocument '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:PassRole"],"Resource":"*"}}'
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -JsonDocumentTokenized ('{"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINstaNces","IA\u004D:pasSroLE"],"Re\u0073o\u0075rce":"*"}}' | ConvertTo-JsonObject -Target JsonTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -JsonDocumentTokenized ('{  "Version" :"20\u0031\u0032-1\u0030-17"  ,  "Statement":{   "Ef\u0066ect":"\u0041l\u006Co\u0077",  "Action":   ["Ec2:RunINstaNce***s" , "IA\u004D:pas??oLE"],  "Re\u0073o\u0075rce" : "\u002A"  }  }' | ConvertTo-JsonObject -Target JsonTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Remove-ObfuscationLayer
C:\PS> $obfContainer.History | Select-Object Layer,JsonDocumentSize,JsonDocument

Layer JsonDocumentSize JsonDocument
----- ---------------- ------------
    0              115 {"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:RunInstances","iam:Pas…
    1              145 {"Version":"2012-10-17","Statement":{"Effect":"\u0041l\u006Co\u0077","Action":["Ec2:RunINst…

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $ObfuscationContainer
    )

    begin
    {

    }

    process
    {
        # Iterate over each input -ObfuscationContainer object.
        foreach ($curObfuscationContainer in $ObfuscationContainer)
        {
            # Handle obfuscation layer removal based on current Layer property count.
            if ($curObfuscationContainer.Layer -eq 0)
            {
                Write-Warning "Current obfuscation container is Layer=0 so no obfuscation layers exist to remove."
            }
            else
            {
                # Make copy of $curObfuscationContainer PSCustomObject so changes in this function do not affect input -ObfuscationContainer object outside this function.
                $curObfuscationContainer = $curObfuscationContainer.PSObject.Copy()

                # Update relevant main values in $curObfuscationContainer from next-to-last History property.
                $curObfuscationContainer.Layer                     = $curObfuscationContainer.History[-2].Layer
                $curObfuscationContainer.JsonDocument              = $curObfuscationContainer.History[-2].JsonDocument
                $curObfuscationContainer.JsonDocumentTokenized     = $curObfuscationContainer.History[-2].JsonDocumentTokenized
                $curObfuscationContainer.JsonDocumentSize          = $curObfuscationContainer.History[-2].JsonDocumentSize
                $curObfuscationContainer.JsonDocumentTokenizedSize = $curObfuscationContainer.History[-2].JsonDocumentTokenizedSize
                $curObfuscationContainer.JsonDocumentValueCount    = $curObfuscationContainer.History[-2].JsonDocumentValueCount
                $curObfuscationContainer.JsonDocumentDepth         = $curObfuscationContainer.History[-2].JsonDocumentDepth
                $curObfuscationContainer.JsonDocumentMD5           = $curObfuscationContainer.History[-2].JsonDocumentMD5

                # Remove last object in $curObfuscationContainer's History property.
                $curObfuscationContainer.History = @($curObfuscationContainer.History[0..($curObfuscationContainer.History.Count - 2)])
            }

            # Return current updated obfuscation container object.
            $curObfuscationContainer
        }
    }

    end
    {

    }
}


function Get-FunctionInfo
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

Invoke-SkyScalpel Function: Get-FunctionInfo
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-FunctionInfo extracts function name and input parameters from input $MyInvocation automatic variable to provide standardized function parameter input the user would enter to replicate the function call. It is used for displaying current function's input parameters for error handling purposes as well as tracking ExecutionCommands values in Invoke-SkyScalpel UI.

.PARAMETER MyInvocation

Specifies $MyInvocation automatic variable from which the function name and input parameters will be extracted.

.EXAMPLE

C:\PS> function Out-Test ([System.String] $ArgString, [Int16[]] $ArgIntArray) { Write-Host "`n[Out-Test] -ArgString = $ArgString and ArgIntArray = $ArgIntArray"; $MyInvocation | Get-FunctionInfo }
C:\PS> Out-Test -ArgString "TESTING" -ArgIntArray @(1..3)

[Out-Test] -ArgString = TESTING and ArgIntArray = 1 2 3

Name     ArgArray                                                               ArgString                               CommandLineSyntax                               
----     --------                                                               ---------                               -----------------                               
Out-Test {@{Key=-ArgString; Value=TESTING}, @{Key=-ArgIntArray; Value=@(1..3)}} -ArgString TESTING -ArgIntArray @(1..3) Out-Test -ArgString TESTING -ArgIntArray @(1..3)

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.InvocationInfo]
        $MyInvocation
    )

    begin
    {

    }

    process
    {
        # Extract function name, argument(s) (as both array and string) and final commandline argument syntax as a string.
        $functionName = [System.String] $MyInvocation.MyCommand.Name
        $functionArgArray = [System.Object[]] $MyInvocation.BoundParameters.GetEnumerator().Where( { $_.Key -ne 'ObfuscationContainer' } ) | ForEach-Object {
            # Handle cleaner display of array syntax.
            if (($_.Value.GetType().Name -in @('Int16[]','Int32[]','Int64[]')) -and ($_.Value.Count -gt 1))
            {
                # Handle sorted shorthand array syntax. E.g. 1 2 3 4 5 --> @(1..5) instead of @(1,2,3,4,5)
                $sortedValue = ($_.Value | Sort-Object)
                if (-not (Compare-Object -ReferenceObject @($sortedValue[0]..$sortedValue[-1]) -DifferenceObject $_.Value))
                {
                    [PSCustomObject] @{
                        Key   = [System.String] "-$($_.Key)"
                        Value = [System.String] "@($($sortedValue[0])..$($sortedValue[-1]))"
                    }
                }
                else
                {
                    [PSCustomObject] @{
                        Key   = [System.String] "-$($_.Key)"
                        Value = [System.String] "@($(($_.Value | Sort-Object) -join ','))"
                    }
                }
            }
            elseif (($_.Value.GetType().Name -eq 'Char[]') -and ($_.Value.Count -gt 1))
            {
                $arrayValue = $_.Value | ForEach-Object {
                    if ($_ -eq "'")
                    {
                        "`"$_`""
                    }
                    else
                    {
                        "'$_'"
                    }
                }
                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] "@($($arrayValue -join ','))"
                }
            }
            elseif ($_.Value.GetType().Name.EndsWith('[]') -and ($_.Value.Count -gt 1))
            {
                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] ($_.Value -join ',')
                }
            }
            else
            {
                # For a subset of properties (Command, JsonDocument and JsonDocumentPath) encapsulate value in single quotes and perform proper escaping of quotes.
                if ($_.Key -in @('Command','JsonDocument','JsonDocumentPath'))
                {
                    $curValue = "'" + $_.Value.Replace("'","''") + "'"
                }
                else
                {
                    $curValue = $_.Value
                }

                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] $curValue
                }
            }
        }
        $functionArgString = [System.String] ($functionArgArray | ForEach-Object { $_.Key; $_.Value }) -join ' '
        $commandLineSyntax = [System.String] "$functionName $functionArgString"

        # Return extracted function values as PSCustomObject.
        [PSCustomObject] @{
            Name              = $functionName
            ArgArray          = $functionArgArray
            ArgString         = $functionArgString
            CommandLineSyntax = $commandLineSyntax
        }
    }

    end
    {

    }
}