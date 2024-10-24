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



function ConvertTo-RandomCase
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-RandomCase
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: None

.DESCRIPTION

ConvertTo-RandomCase randomly inverts case of eligible alpha character(s) in input string.

.PARAMETER InputObject

Specifies string in which to invert case of eligible alpha character(s).

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.EXAMPLE

PS C:\> 'Kosovë' | ConvertTo-RandomCase

kOsOvË

.EXAMPLE

PS C:\> 'Ko\u0073ov\u00EB' | ConvertTo-RandomCase -RandomCharPercent 75

kO\u0053OV\u00CB

.EXAMPLE

PS C:\> '"Kukës"' | ConvertTo-RandomCase -RandomCharPercent 100 -Include 'K','k','ë'

"kuKËs"

.EXAMPLE

PS C:\> '"Kukës"' | ConvertTo-RandomCase -RandomCharPercent 100 -Exclude 'K','k','ë'

"KUkëS"

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
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Include,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Exclude
    )

    # Parse -InputObject as JSON string value so deeper validation checks
    # and more precise obfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_

        # Extract content of current parsed character for case modification.
        # Retrieve decoded content for unicode encoded characters so underlying value can have
        # its case randomized and converted back to unicode encoded syntax at end of function.
        $curCharToModify = ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Hex) ? $curChar.ContentDecoded : $curChar.Content

        # Set boolean for generic obfuscation eligibility.
        $isEligible = $true

        # Override above obfuscation eligibility for specific scenarios.
        if ($curCharToModify.ToUpper() -ceq $curCharToModify.ToLower())
        {
            # Override obfuscation eligibility for characters with no concept of case.
            # Above logic ensures alpha characters and unicode characters with casing concept remain eligible.
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin $Exclude)
        {
            # Override obfuscation eligibility for decoded characters defined in user input -Exclude parameter.
            $isEligible = $false
        }
        elseif ($Include -and $curChar.ContentDecoded -cnotin $Include)
        {
            # Override obfuscation eligibility for decoded characters not defined in user input -Include parameter (if it is explicitly defined).
            $isEligible = $false
        }

        # Set boolean for obfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for obfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Invert case of current alpha character (or any unicode character with casing concept, e.g. 'ë' => 'Ë').
            $curCharModified = $curCharToModify.ToUpper() -cne $curCharToModify ? $curCharToModify.ToUpper() : $curCharToModify.ToLower()

            # If modification successfully applied above then update current parsed character's Content property with modified value.
            if ($curCharModified -cne $curCharToModify)
            {
                # If current parsed character was originally unicode encoded then convert modified value back to unicode encoded syntax.
                if ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Hex)
                {
                    # Determine if potential alpha character(s) in unicode encoded syntax should be uppercase or lowercase
                    # (e.g. \u006a versus \u006A) based on casing of original unicode encoded syntax.
                    $unicodeFormatStr = switch -Regex -CaseSensitive ($curChar.Content -creplace '^\\u','')
                    {
                        '[A-Z]' { '{0:X4}'; break }
                        '[a-z]' { '{0:x4}'; break }
                        default { Get-Random -InputObject @('{0:X4}','{0:x4}') }
                    }
                    $curChar.Content = '\u' + [System.String]::Format($unicodeFormatStr, [System.Byte] [System.Char] $curCharModified)
                }
                else
                {
                    $curChar.Content = $curCharModified
                }
            }
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Return final result.
    $inputObjectModified
}


function ConvertTo-RandomUnicode
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-RandomUnicode
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: None

.DESCRIPTION

ConvertTo-RandomUnicode randomly substitutes eligible character(s) in input string with equivalent unicode encoding syntax.

.PARAMETER InputObject

Specifies string in which to substitute eligible character(s) with equivalent unicode encoding syntax.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.PARAMETER Case

(Optional) Specifies case option(s) for potential alpha characters in unicode encoding syntax (e.g. \u006a versus \u006A).

.EXAMPLE

PS C:\> 'Kosovë' | ConvertTo-RandomUnicode

\u004Bo\u0073ov\u00EB

.EXAMPLE

PS C:\> 'Ko\u0073ov\u00EB' | ConvertTo-RandomUnicode -RandomCharPercent 75 -Case Lower

\u004bo\u0073\u006f\u0076\u00EB

.EXAMPLE

PS C:\> 'Ko\u0073ov\u00EB' | ConvertTo-RandomUnicode -RandomCharPercent 75 -Case Upper

\u004B\u006F\u0073\u006F\u0076\u00EB

.EXAMPLE

PS C:\> '"Kukës"' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Include 'K','k','ë'

"\u004Bu\u006B\u00EBs"

.EXAMPLE

PS C:\> '"Kukës"' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Exclude 'K','k','ë'

"K\u0075kë\u0073"

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
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Include,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Exclude,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Upper','Lower')]
        [System.String[]]
        $Case = @('Upper','Lower')
    )

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise obfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_

        # Set boolean for generic obfuscation eligibility.
        $isEligible = $true

        # Override above obfuscation eligibility for specific scenarios.
        if (
            $curChar.Format -in @(
                [SkyScalpel.JsonStringParsedFormat]::Hex
                [SkyScalpel.JsonStringParsedFormat]::Protected
                [SkyScalpel.JsonStringParsedFormat]::EscapedUnknown
            )
        )
        {
            # Override obfuscation eligibility for characters that are already unicode
            # encoded (e.g. '\u0061'), are a protected value (e.g. leading/trailing
            # double quote for string values) or are unknown escapes (e.g. '\c').
            $isEligible = $false
        }
        elseif ($curChar.Content -cin $Exclude)
        {
            # Override obfuscation eligibility for characters defined in user input -Exclude parameter.
            $isEligible = $false
        }
        elseif ($Include -and $curChar.Content -cnotin $Include)
        {
            # Override obfuscation eligibility for characters not defined in user input -Include parameter (if it is explicitly defined).
            $isEligible = $false
        }

        # Set boolean for obfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for obfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Convert extracted decoded content of current parsed character to its equivalentunicode encoding syntax.
            # Randomly select if potential alpha character(s) in unicode encoded syntax should be uppercase or lowercase
            # (e.g. \u006a versus \u006A).
            $unicodeFormatStr = (Get-Random -InputObject $Case) -ieq 'Upper' ? '{0:X4}' : '{0:x4}'
            $curCharModified = '\u' + [System.String]::Format($unicodeFormatStr, [System.Byte] [System.Char] $curChar.ContentDecoded)

            # Update current parsed character object's Content property with unicode encoding syntax above.
            $curChar.Content = $curCharModified
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Return final result.
    $inputObjectModified
}


function ConvertTo-RandomWildcard
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-RandomWildcard
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: ConvertTo-RandomUnicode

.DESCRIPTION

ConvertTo-RandomWildcard randomly adds or substitutes eligible character(s) in input string with wildcard character(s).

.PARAMETER InputObject

Specifies string in which to add or substitute eligible character(s) with wildcard character(s).

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER RandomLength

(Optional) Specifies eligible length(s) for each random wildcard string.

.PARAMETER Format

(Optional) Specifies eligible format(s) for each random wildcard string (e.g. plaintext, unicode or format matching original eligible characters).

.PARAMETER Type

(Optional) Specifies eligible type(s) of obfuscation (e.g. inserting before, after or replacing original eligible characters).

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.EXAMPLE

PS C:\> 'CreateUser' | ConvertTo-RandomWildcard

Cr***e\u002aat*e\u002a\u002as***er

.EXAMPLE

PS C:\> 'Cre\u0061teUs\u0065r' | ConvertTo-RandomWildcard -RandomCharPercent 100 -Include 'a','e'

Cr***\u002A\u0061t*eUs\u0065\u002a\u002ar

.EXAMPLE

PS C:\> '"Cre\u0061teUs\u0065r"' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Matching -Type Replace -Include 'a','e'

"Cr*\u002at*Us\u002Ar"

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
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(1,100)]
        [System.Int16[]]
        $RandomLength = @(1,2,3),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'Plaintext',
            'Unicode',
            'Matching'
        )]
        [System.String[]]
        $Format = @('Plaintext','Unicode','Matching'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'InsertBefore',
            'InsertAfter',
            'Replace'
        )]
        [System.String[]]
        $Type = @('InsertBefore','InsertAfter','Replace'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Include,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Exclude
    )

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise obfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_

        # Set boolean for generic obfuscation eligibility.
        $isEligible = $true

        # Override above obfuscation eligibility for specific scenarios.
        if ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Protected)
        {
            # Override obfuscation eligibility for characters that are a protected value (e.g. leading/trailing
            # double quote for string values).
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin @('*','?'))
        {
            # Override obfuscation eligibility for wildcard characters (e.g. '*' or '?').
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin $Exclude)
        {
            # Override obfuscation eligibility for decoded characters defined in user input -Exclude parameter.
            $isEligible = $false
        }
        elseif ($Include -and $curChar.ContentDecoded -cnotin $Include)
        {
            # Override obfuscation eligibility for decoded characters not defined in user input -Include parameter (if it is explicitly defined).
            $isEligible = $false
        }

        # Set boolean for obfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for obfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Select random obfuscation type from user input -Type parameter (if multiple values are defined).
            $curType = Get-Random -InputObject $Type

            # Select random obfuscation format from user input -Format parameter (if multiple values are defined).
            $curFormat = Get-Random -InputObject $Format

            # If random obfuscation format above is 'Matching' then normalize to 'Unicode' or 'Plaintext'
            # based on format of current character.
            if ($curFormat -ieq 'Matching')
            {
                $curFormat = ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Hex) ? 'Unicode' : 'Plaintext'
            }

            # Generate random wildcard string where length is based on user input -RandomLength parameter
            # and format is based on user input -Format parameter.
            $randomWildcardLength = Get-Random -InputObject $RandomLength
            $randomWildcardStr = switch ($curFormat)
            {
                'Plaintext' { -join('*' * $randomWildcardLength) }
                'Unicode'   { -join('*' * $randomWildcardLength) | ConvertTo-RandomUnicode -RandomCharPercent 100 }
                default     { Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_" }
            }

            # Add or substitute current character with wildcard string based on random obfuscation type selected above.
            $curCharModified = switch ($curType)
            {
                'InsertAfter'  { $curChar.Content + $randomWildcardStr }
                'InsertBefore' { $randomWildcardStr + $curChar.Content }
                'Replace'      { $randomWildcardStr }
                default        { Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_" }
            }

            # Update current parsed character object's Content property with wildcard obfuscation syntax above.
            $curChar.Content = $curCharModified
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Return final result.
    $inputObjectModified
}


function ConvertTo-RandomWildcardSingleChar
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-RandomWildcardSingleChar
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: ConvertTo-RandomUnicode

.DESCRIPTION

ConvertTo-RandomWildcardSingleChar randomly substitutes eligible character(s) in input string with single-character wildcard character(s).

.PARAMETER InputObject

Specifies string in which to substitute eligible character(s) with single-character wildcard character(s).

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Format

(Optional) Specifies eligible format(s) for each random single-character wildcard string (e.g. plaintext, unicode or format matching original eligible characters).

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.EXAMPLE

PS C:\> 'CreateUser' | ConvertTo-RandomWildcardSingleChar

Cr\u003fate\u003Fs?r

.EXAMPLE

PS C:\> 'Cr\u003fate\u003Fs?r' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Include 'a','e'

Cr\u003f?t?\u003Fs?r

.EXAMPLE

PS C:\> '"Cre\u0061teUs\u0065r"' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Matching -Include 'a','e'

"Cr?\u003Ft?Us\u003Fr"

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
        [System.String]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'Plaintext',
            'Unicode',
            'Matching'
        )]
        [System.String[]]
        $Format = @('Plaintext','Unicode','Matching'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Include,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Exclude
    )

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise obfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_

        # Set boolean for generic obfuscation eligibility.
        $isEligible = $true

        # Override above obfuscation eligibility for specific scenarios.
        if ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Protected)
        {
            # Override obfuscation eligibility for characters that are a protected value (e.g. leading/trailing
            # double quote for string values).
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin @('*','?'))
        {
            # Override obfuscation eligibility for wildcard characters (e.g. '*' or '?').
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin $Exclude)
        {
            # Override obfuscation eligibility for decoded characters defined in user input -Exclude parameter.
            $isEligible = $false
        }
        elseif ($Include -and $curChar.ContentDecoded -cnotin $Include)
        {
            # Override obfuscation eligibility for decoded characters not defined in user input -Include parameter (if it is explicitly defined).
            $isEligible = $false
        }

        # Set boolean for obfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for obfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Select random obfuscation format from user input -Format parameter (if multiple values are defined).
            $curFormat = Get-Random -InputObject $Format

            # If random obfuscation format above is 'Matching' then normalize to 'Unicode' or 'Plaintext'
            # based on format of current character.
            if ($curFormat -ieq 'Matching')
            {
                $curFormat = ($curChar.Format -eq [SkyScalpel.JsonStringParsedFormat]::Hex) ? 'Unicode' : 'Plaintext'
            }

            # Generate random wildcard string where format is based on user input -Format parameter.
            $randomWildcardStr = switch ($curFormat)
            {
                'Plaintext' { '?' }
                'Unicode'   { '?' | ConvertTo-RandomUnicode -RandomCharPercent 100 }
                default     { Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_" }
            }

            # Substitute current character with single-character wildcard string based on random obfuscation type selected above.
            $curCharModified = $randomWildcardStr

            # Update current parsed character object's Content property with wildcard obfuscation syntax above.
            $curChar.Content = $curCharModified
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Return final result.
    $inputObjectModified
}