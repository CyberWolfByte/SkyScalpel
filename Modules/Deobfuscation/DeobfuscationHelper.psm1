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



function ConvertFrom-RandomUnicode
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertFrom-RandomUnicode
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-RandomUnicode randomly substitutes eligible unicode encoded character(s) in input string with equivalent decoded syntax.

.PARAMETER InputObject

Specifies string in which to substitute eligible unicode encoded character(s) with equivalent decoded syntax.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit deobfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude deobfuscation eligibility.

.EXAMPLE

PS C:\> '\u004Bo\u0073ov\u00EB' | ConvertFrom-RandomUnicode

Ko\u0073ovë

.EXAMPLE

PS C:\> '\u004Bo\u0073ov\u00EB' | ConvertFrom-RandomUnicode -RandomCharPercent 75

Kosovë

.EXAMPLE

PS C:\> '"\u004Bu\u006B\u00EBs"' | ConvertFrom-RandomUnicode -RandomCharPercent 100 -Include 'K','k','ë'

"Kukës"

.EXAMPLE

PS C:\> '"K\u0075kë\u0073"' | ConvertFrom-RandomUnicode -RandomCharPercent 100 -Exclude 'K','k','ë'

"Kukës"

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

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise deobfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_

        # Set boolean for generic deobfuscation eligibility.
        $isEligible = $true

        # Override above deobfuscation eligibility for specific scenarios.
        if ($curChar.Format -ne [SkyScalpel.JsonStringParsedFormat]::Hex)
        {
            # Override deobfuscation eligibility for characters that are not
            # unicode encoded (e.g. '\u0061').
            $isEligible = $false
        }
        elseif ($curChar.ContentDecoded -cin $Exclude)
        {
            # Override deobfuscation eligibility for characters defined in
            # user input -Exclude parameter.
            $isEligible = $false
        }
        elseif ($Include -and $curChar.ContentDecoded -cnotin $Include)
        {
            # Override deobfuscation eligibility for characters not defined in
            # user input -Include parameter (if it is explicitly defined).
            $isEligible = $false
        }

        # Set boolean for deobfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for deobfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Update current parsed character object's Content property with ContentDecoded property.
            $curChar.Content = $curChar.ContentDecoded
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Return final result.
    $inputObjectModified
}


function ConvertFrom-RandomWildcard
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertFrom-RandomWildcard
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-RandomWildcard randomly substitutes eligible wildcard character(s) in input Action string with plaintext Action prefixes, suffixes or substrings (or simply removes unnecessary wildcard characters).

.PARAMETER InputObject

Specifies Action string in which to substitute eligible wildcard character(s) with plaintext Action prefixes, suffixes or substrings (or simply removes unnecessary wildcard characters).

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER RandomLength

(Optional) Specifies maximum eligible length(s) for each plaintext prefix, suffix or substring to add back to input Action string.

.PARAMETER Type

(Optional) Specifies eligible type(s) of deobfuscation (e.g. Adjacent, Prefix, Suffix, Substring).

.EXAMPLE

PS C:\> 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 10

iam:CreateAccessKey

.EXAMPLE

PS C:\> 'iam:C***teA**y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -Type Adjacent

iam:C*teA*y

.EXAMPLE

PS C:\> 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Type Prefix

iam:Cre*teAcc*y

.EXAMPLE

PS C:\> 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Type Suffix

iam:C*eateA*Key

.EXAMPLE

PS C:\> 'iam:?r*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Type Substring

iam:?reateA*cc*y

.EXAMPLE

PS C:\> 'lambda:Li*Fu*s' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 10

lambda:ListFunction*s

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
            'Adjacent',
            'Prefix',
            'Suffix',
            'Substring'
        )]
        [System.String[]]
        $Type = @('Adjacent','Prefix','Suffix','Substring')
    )

    # Retrieve normalized list of Action value(s) for original Action value.
    $actionList = (Get-AwsAction -Name $InputObject).Action

    # Return original Action value if it does not resolve to any list of Action values.
    if ($actionList.Count -eq 0)
    {
        return $InputObject
    }

    # Capture original user input -Type parameter value so $Type variable can
    # be updated to original value in each loop iteration below in case it is
    # modified in certain filtering scenarios below.
    $origType = $Type

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise deobfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $index = -1
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_
        $index++

        # Update $Type variable with original value of user input -Type parameter in case
        # it was modified in certain filtering scenarios below in previous iteration.
        $Type = $origType

        # Set boolean for generic deobfuscation eligibility.
        $isEligible = $true

        # Override above deobfuscation eligibility for specific scenarios.
        if ($curChar.ContentDecoded -cne '*')
        {
            # Override deobfuscation eligibility for characters that are not wildcard
            # characters (encoded or decoded).
            $isEligible = $false
        }
        else
        {
            # Set boolean if either adjacent character is a wildcard character (encoded or decoded).
            $hasAdjacentWildcard = (
                (($index -gt 0) -and $inputObjectParsed[$index - 1].ContentDecoded -ceq '*') -or
                ((($index + 1) -lt $inputObjectParsed.Count) -and $inputObjectParsed[$index + 1].ContentDecoded -ceq '*')
            )

            # Remove 'Adjacent' from user input -Type parameter (for current iteration only) if it
            # is present but neither adjacent character is a wildcard character (encoded or decoded).
            if ($Type -icontains 'Adjacent' -and -not $hasAdjacentWildcard)
            {
                $Type = $Type.Where( { $_ -ine 'Adjacent' } )
            }

            if ($Type.Count -eq 0)
            {
                # Override deobfuscation eligibility if 'Adjacent' was the only value defined
                # in user input -Type parameter but no adjacent wildcard characters are present.
                $isEligible = $false
            }
        }

        # Set boolean for deobfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for deobfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Select random deobfuscation type from user input -Type parameter (if multiple values are defined).
            $curType = Get-Random -InputObject $Type

            # Perform wildcard deobfuscation based on current user input -Type parameter.
            switch ($curType)
            {
                'Adjacent' {
                    # Update current parsed character object's Content and ContentDecoded properties
                    # to null to effectively remove current wildcard character.
                    $curChar.Content = $curChar.ContentDecoded = $null
                }
                default {
                    # Create regex with greedy capture group to extract plaintext substring(s) from
                    # normalized list of Action value(s) for original Action value.
                    $plaintextPrefixRegex = [SkyScalpel.JsonParser]::ConvertToValidRegex(-join($inputObjectParsed | Select-Object -First $index).ContentDecoded, $true)
                    $plaintextSuffixRegex = [SkyScalpel.JsonParser]::ConvertToValidRegex(-join($inputObjectParsed | Select-Object -Skip ($index + 1)).ContentDecoded, $true)
                    $plaintextSubstrRegex = -join@(
                        '^'
                        $plaintextPrefixRegex
                        '(.*)'
                        $plaintextSuffixRegex
                        '$'
                    )

                    # Using greedy regex above extract plaintext substring(s) from normalized list
                    # of Action value(s) for original Action value.
                    $actionListSubstrArr = $actionList.ForEach( { $_ -imatch $plaintextSubstrRegex ? $matches[1] : $null } ) | Sort-Object -Unique
                    $actionListSubstrArrMaxLength = ($actionListSubstrArr.ForEach( { $_.Length } ) | Measure-Object -Maximum).Maximum

                    # If no Action substring(s) extracted then wildcard is unnecessary, so remove it.
                    if ($actionListSubstrArrMaxLength -eq 0)
                    {
                        # Update current parsed character object's Content and ContentDecoded properties
                        # to null to effectively remove current wildcard character.
                        $curChar.Content = $curChar.ContentDecoded = $null

                        continue
                    }

                    # If at least one Action does not have an eligible substring extracted but all
                    # other extracted Action substrings begin with the same letter (case-insensitive)
                    # as the plaintext suffix following current wildcard character then wildcard is
                    # unnecessary, so remove it.
                    if (
                        $plaintextSuffixRegex -and
                        $actionListSubstrArr.Where( { $_.Length -eq 0 } ).Count -gt 0 -and
                        $actionListSubstrArr.Where( { $_.Length -gt 0 -and $_[0] -ieq $plaintextSuffixRegex[0] } ).Count -eq $actionListSubstrArr.Where( { $_.Length -gt 0 } ).Count
                    )
                    {
                        # Update current parsed character object's Content and ContentDecoded properties
                        # to null to effectively remove current wildcard character.
                        $curChar.Content = $curChar.ContentDecoded = $null

                        continue
                    }

                    # If Action substring(s) extracted but at least one Action does not have any
                    # eligible substring then no wildcard removal can occur.
                    if ($actionListSubstrArr.Count -gt 0 -and $actionListSubstrArr.Where( { $_.Length -eq 0 } ).Count -gt 0)
                    {
                        continue
                    }

                    # Calculate case-insensitive longest common prefix, suffix and substring for
                    # substituting current wildcard character based on user input -Type parameter.
                    $longestCommonObj = [PSCustomObject] @{
                        Prefix    = $Type -icontains 'Prefix'    ? ($actionListSubstrArr | Out-LongestCommonPrefix   ) : $null
                        Substring = $Type -icontains 'Substring' ? ($actionListSubstrArr | Out-LongestCommonSubstring) : $null
                        Suffix    = $Type -icontains 'Suffix'    ? ($actionListSubstrArr | Out-LongestCommonSuffix   ) : $null
                    }

                    # Remove any user input -Type parameter value(s) whose corresponding
                    # substring extracted above is null.
                    $nonNullTypeArr = $longestCommonObj.PSObject.Members.Where( { $_.MemberType -eq 'NoteProperty' -and $_.Value.Length -gt 0 }).Name
                    $eligibleTypeArr = $Type.Where( { $_ -iin $nonNullTypeArr } )

                    # Continue to next object in parsed -InputObject value if no eligible
                    # user input -Type parameter remains for current extracted substring(s).
                    if ($eligibleTypeArr.Count -eq 0)
                    {
                        continue
                    }

                    # Select random eligible deobfuscation type from user input -Type parameter (if multiple values are defined).
                    $curType = Get-Random -InputObject $eligibleTypeArr

                    # Set variables for potential wildcard prefix and suffix based on adjacent character.
                    $wildcardPrefix = (($index -gt 0) -and ($inputObjectParsed[$index - 1].ContentDecoded -ceq '*' -or $inputObjectParsed[$index - 1].ContentDecoded -cmatch '[^\\]\*$'))                           ? $null : $curChar.Content
                    $wildcardSuffix = ((($index + 1) -lt $inputObjectParsed.Count) -and ($inputObjectParsed[$index + 1].ContentDecoded -ceq '*' -or $inputObjectParsed[$index + 1].ContentDecoded.StartsWith('*'))) ? $null : $curChar.Content

                    # Generate final plaintext substring based on current user input -Type parameter.
                    $plaintextSubstr = switch ($curType)
                    {
                        'Prefix' {
                            # Potentially shorten longest prefix substring based on user input -RandomLength parameter.
                            if ($longestCommonObj.Prefix.Length -gt 0)
                            {
                                # Select random deobfuscation length from user input -RandomLength parameter (if
                                # multiple values are defined) with a ceiling of the current prefix substring length.
                                $curRandomLength = Get-Random -InputObject $RandomLength
                                $curRandomLength = $curRandomLength -gt $longestCommonObj.Prefix.Length ? $longestCommonObj.Prefix.Length : $curRandomLength

                                # Potentially shorten longest prefix substring.
                                $longestCommonObj.Prefix = $longestCommonObj.Prefix.Substring(0,$curRandomLength)
                            }

                            # Return prefix substring followed by original wildcard character (unless prefix
                            # substring is entire missing substring).
                            if ($longestCommonObj.Prefix.Length -eq $actionListSubstrArrMaxLength)
                            {
                                $longestCommonObj.Prefix
                            }
                            else
                            {
                                $longestCommonObj.Prefix + $wildcardSuffix
                            }
                        }
                        'Substring' {
                            # Potentially shorten longest substring based on user input -RandomLength parameter.
                            if ($longestCommonObj.Substring.Length -gt 0)
                            {
                                # Select random deobfuscation length from user input -RandomLength parameter (if
                                # multiple values are defined) with a ceiling of the current substring length.
                                $curRandomLength = Get-Random -InputObject $RandomLength
                                $curRandomLength = $curRandomLength -gt $longestCommonObj.Substring.Length ? $longestCommonObj.Substring.Length : $curRandomLength

                                # Potentially shorten longest substring.
                                $curRandomStartIndex = Get-Random -Minimum 0 -Maximum ($longestCommonObj.Substring.Length - $curRandomLength + 1)
                                $longestCommonObj.Substring = $longestCommonObj.Substring.Substring($curRandomStartIndex,$curRandomLength)
                            }

                            # Return substring followed and/or preceeded by original wildcard character (unless
                            # substring is entire missing substring).
                            if ($longestCommonObj.Substring.Length -eq $actionListSubstrArrMaxLength)
                            {
                                $longestCommonObj.Substring
                            }
                            else
                            {
                                # Determine if longest substring overlaps with longest prefix or suffix and
                                # potentially set wildcard prefix and/or suffix values to null accordingly.
                                $overlapsWithPrefix = $longestCommonObj.Prefix.Length -gt 0 -and $longestCommonObj.Substring.StartsWith($longestCommonObj.Prefix)
                                $overlapsWithSuffix = $longestCommonObj.Suffix.Length -gt 0 -and $longestCommonObj.Substring.EndsWith($longestCommonObj.Suffix)
                                $wildcardPrefix = $overlapsWithPrefix ? $null : $wildcardPrefix
                                $wildcardSuffix = $overlapsWithSuffix ? $null : $wildcardSuffix

                                $wildcardPrefix + $longestCommonObj.Substring + $wildcardSuffix
                            }
                        }
                        'Suffix' {
                            # Potentially shorten longest suffix substring based on user input -RandomLength parameter.
                            if ($longestCommonObj.Suffix.Length -gt 0)
                            {
                                # Select random deobfuscation length from user input -RandomLength parameter (if
                                # multiple values are defined) with a ceiling of the current suffix substring length.
                                $curRandomLength = Get-Random -InputObject $RandomLength
                                $curRandomLength = $curRandomLength -gt $longestCommonObj.Suffix.Length ? $longestCommonObj.Suffix.Length : $curRandomLength

                                # Potentially shorten longest suffix substring.
                                $longestCommonObj.Suffix = $longestCommonObj.Suffix.Substring($longestCommonObj.Suffix.Length - $curRandomLength)
                            }

                            # Return suffix substring followed by original wildcard character (unless suffix
                            # substring is entire missing substring).
                            if ($longestCommonObj.Suffix.Length -eq $actionListSubstrArrMaxLength)
                            {
                                $longestCommonObj.Suffix
                            }
                            else
                            {
                                $wildcardPrefix + $longestCommonObj.Suffix
                            }
                        }
                    }

                    # Update current parsed character object's Content and ContentDecoded properties
                    # to final plaintext substring.
                    $curChar.Content = $curChar.ContentDecoded = $plaintextSubstr
                }
            }
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Retrieve normalized list of Action value(s) for modified Action value.
    $actionListModified = (Get-AwsAction -Name $inputObjectModified).Action

    # Return original Action value if modified Action value does not produce the
    # same normalized list of Action value(s) as the original Action value.
    if (
        $actionListModified.Count -eq 0 -or
        (Compare-Object -ReferenceObject $actionList -DifferenceObject $actionListModified).Count -gt 0
    )
    {
        return $InputObject
    }

    # Return final result.
    $inputObjectModified
}


function ConvertFrom-RandomWildcardSingleChar
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertFrom-RandomWildcardSingleChar
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-JsonParsedValue
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-RandomWildcardSingleChar randomly substitutes eligible single-character wildcard character(s) in input Action string with plaintext Action single-character substrings.

.PARAMETER InputObject

Specifies Action string in which to substitute eligible single-character wildcard character(s) with plaintext Action single-character substrings.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.EXAMPLE

PS C:\> 'iam:Cr??teAcce??Key' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 100

iam:CreateAccessKey

.EXAMPLE

PS C:\> 'iam:Cr??teAcce??Key' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 50

iam:Cre?teAcce?sKey

.EXAMPLE

PS C:\> 'iam:?r*A??e??Ke?' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 100

iam:Cr*AccessKey

.EXAMPLE

PS C:\> 'lambda:Li??Fu??ti??*s' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 100

lambda:ListFunction*s

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
        $RandomCharPercent = 50
    )

    # Retrieve normalized list of Action value(s) for original Action value.
    $actionList = (Get-AwsAction -Name $InputObject).Action

    # Return original Action value if it does not resolve to any list of Action values.
    if ($actionList.Count -eq 0)
    {
        return $InputObject
    }

    # Parse -InputObject as JSON string value so deeper validation checks and
    # more precise deobfuscation can be performed.
    $inputObjectParsed = ConvertTo-JsonParsedValue -InputObject $InputObject

    # Iterate over each object in parsed -InputObject value.
    $index = -1
    $inputObjectModified = -join$inputObjectParsed.ForEach(
    {
        $curChar = $_
        $index++

        # Set boolean for generic deobfuscation eligibility.
        $isEligible = $true

        # Override above deobfuscation eligibility for specific scenarios.
        if ($curChar.ContentDecoded -cne '?')
        {
            # Override deobfuscation eligibility for characters that are not single-character wildcard
            # characters (encoded or decoded).
            $isEligible = $false
        }

        # Set boolean for deobfuscation eligibility based on user input -RandomCharPercent value.
        $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

        # Proceed if eligible for deobfuscation.
        if ($isEligible -and $isRandomCharPercent)
        {
            # Create regex with capture group to extract single-character plaintext substring(s)
            # from normalized list of Action value(s) for original Action value.
            $plaintextPrefixRegex = [SkyScalpel.JsonParser]::ConvertToValidRegex(-join($inputObjectParsed | Select-Object -First $index).ContentDecoded)
            $plaintextSuffixRegex = [SkyScalpel.JsonParser]::ConvertToValidRegex(-join($inputObjectParsed | Select-Object -Skip ($index + 1)).ContentDecoded)
            $plaintextSubstrRegex = -join@(
                '^'
                $plaintextPrefixRegex
                '(.)'
                $plaintextSuffixRegex
                '$'
            )

            # Using regex above extract single-character plaintext substring(s) from normalized
            # list of Action value(s) for original Action value.
            $actionListSubstrArr = $actionList.ForEach( { $_ -imatch $plaintextSubstrRegex ? $matches[1] : $null } ) | Sort-Object -Unique

            # If only one single-character plaintext substring is extracted then update
            # current parsed character object's Content and ContentDecoded properties
            # to extracted plaintext character.
            if ($actionListSubstrArr.Count -eq 1)
            {
                $curChar.Content = $curChar.ContentDecoded = $actionListSubstrArr[0]
            }
        }

        # Return current parsed character object's Content property value.
        $curChar.Content
    } )

    # Retrieve normalized list of Action value(s) for modified Action value.
    $actionListModified = (Get-AwsAction -Name $inputObjectModified).Action

    # Return original Action value if modified Action value does not produce the
    # same normalized list of Action value(s) as the original Action value.
    if (
        $actionListModified.Count -eq 0 -or
        (Compare-Object -ReferenceObject $actionList -DifferenceObject $actionListModified).Count -gt 0
    )
    {
        return $InputObject
    }

    # Return final result.
    $inputObjectModified
}


function Out-LongestCommonPrefix
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Out-LongestCommonPrefix
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-LongestCommonPrefix returns longest common prefix from input strings.

.PARAMETER InputObject

Specifies strings from which to extract and return longest common prefix.

.PARAMETER CaseSensitive

(Optional) Specifies case sensitivity is enforced when calculating longest common prefix.

.EXAMPLE

PS C:\> @('Shumë','Shëndet') | Out-LongestCommonPrefix

Sh

.EXAMPLE

PS C:\> @('Art','Arti') | Out-LongestCommonPrefix

Art

.EXAMPLE

PS C:\> @('CreateAccessKey','CreateAccountAlias') | Out-LongestCommonPrefix

CreateAcc

.EXAMPLE

PS C:\> @('ThisIsJson','ThisIsJSON') | Out-LongestCommonPrefix -CaseSensitive

ThisIsJ

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
        [System.String[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $CaseSensitive
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to $inputObjectArr ArrayList.
            $inputObjectArr.AddRange($InputObject)
        }
        else
        {
            # Add single -InputObject object to $inputObjectArr ArrayList.
            $inputObjectArr.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # Cast ArrayList of input objects assembled above to an array of strings.
        $inputObjectArr = [System.String[]] $inputObjectArr

        # Retain copy of first input object so casing of returned longest common prefix will
        # match first input object, especially if user input -CaseSensitive switch parameter
        # is defined causing all input objects to be converted to lowercase below.
        $firstInputObject = $inputObjectArr | Select-Object -First 1

        # Convert all input objects to lowercase if user input -CaseSensitive switch parameter is defined.
        if (-not $PSBoundParameters['CaseSensitive'].IsPresent)
        {
            $inputObjectArr = $inputObjectArr.ForEach( { $_.ToLower() } )
        }

        $longestCommonPrefix = [System.String] $null
        $index = -1
        while ($true)
        {
            $index++

            # Extract character at current index from all input objects.
            $indexCharArr = $inputObjectArr.ForEach( { $_[$index] } ).Where( { $_ } )

            # Break if reached end of any input object.
            if ($indexCharArr.Count -ne $inputObjectArr.Count)
            {
                break
            }

            # Calculate case-sensitive unique list of extracted characters at current index.
            $indexCharArrUniq = $indexCharArr | Sort-Object -Unique -CaseSensitive

            # Break if any differing character(s) found at current index.
            if ($indexCharArrUniq.Count -ne 1)
            {
                break
            }

            # Append current extracted character to longest common prefix string,
            # giving preference to original casing in first input object.
            $longestCommonPrefix += $firstInputObject[$index]
        }

        # Return final result.
        $longestCommonPrefix
    }
}


function Out-LongestCommonSubstring
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Out-LongestCommonSubstring
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-LongestCommonSubstring returns longest common substring from input strings.

.PARAMETER InputObject

Specifies strings from which to extract and return longest common substring.

.PARAMETER CaseSensitive

(Optional) Specifies case sensitivity is enforced when calculating longest common substring.

.EXAMPLE

PS C:\> @('Shumë','Shëndet') | Out-LongestCommonSubstring

Sh

.EXAMPLE

PS C:\> @('Mirë','Kurrë') | Out-LongestCommonSubstring

rë

.EXAMPLE

PS C:\> @('CreateAccessKey','DeleteAccessKey','UpdateAccessKey') | Out-LongestCommonSubstring

teAccessKey

.EXAMPLE

PS C:\> @('ThisIsJson','THISIsJSON') | Out-LongestCommonSubstring -CaseSensitive

IsJ

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
        [System.String[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $CaseSensitive
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to $inputObjectArr ArrayList.
            $inputObjectArr.AddRange($InputObject)
        }
        else
        {
            # Add single -InputObject object to $inputObjectArr ArrayList.
            $inputObjectArr.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # Cast ArrayList of input objects assembled above to an array of strings.
        $inputObjectArr = [System.String[]] $inputObjectArr

        # Extract input object with the shortest length.
        $shortestInputObject = $inputObjectArr | Sort-Object -Property Length | Select-Object -First 1

        # Generate all possible substrings of shortest input object, shuffled and sorted
        # by length in descending order.
        $allPossibleSubstrArr = @(for ($startIndex = 0; $startIndex -lt $shortestInputObject.Length; $startIndex++)
        {
            for ($length = 1; $length -le $shortestInputObject.Length - $startIndex; $length++)
            {
                $shortestInputObject.Substring($startIndex,$length)
            }
        }) | Get-Random -Shuffle | Sort-Object -Property Length -Descending

        # Retain copy of all possible substrings of shortest input object so casing of
        # returned longest common substring will match original substring of shortest
        # input object, especially if user input -CaseSensitive switch parameter
        # is defined causing all input objects and all possible substrings of shortest
        # input objectto be converted to lowercase below.
        $allPossibleSubstrArrOrig = $allPossibleSubstrArr

        # Convert all input objects and all possible substrings of shortest input object to
        # lowercase if user input -CaseSensitive switch parameter is defined.
        if (-not $PSBoundParameters['CaseSensitive'].IsPresent)
        {
            $inputObjectArr = $inputObjectArr.ForEach( { $_.ToLower() } )
            $allPossibleSubstrArr = $allPossibleSubstrArr.ForEach( { $_.ToLower() } )
        }

        # Calculate longest common substring.
        $longestCommonSubstr = foreach ($substr in $allPossibleSubstrArr)
        {
            # Return current substring and break if found in all input objects.
            if ($inputObjectArr.Where( { $_.Contains($substr) } ).Count -eq $inputObjectArr.Count)
            {
                $substr

                break
            }
        }

        # Update longest common substring with original casing in input objects.
        $longestCommonSubstr = $allPossibleSubstrArrOrig.Where( { $_ -ieq $longestCommonSubstr } ) | Select-Object -First 1

        # Return final result.
        $longestCommonSubstr
    }
}


function Out-LongestCommonSuffix
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Out-LongestCommonSuffix
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-LongestCommonSuffix returns longest common suffix from input strings.

.PARAMETER InputObject

Specifies strings from which to extract and return longest common suffix.

.PARAMETER CaseSensitive

(Optional) Specifies case sensitivity is enforced when calculating longest common suffix.

.EXAMPLE

PS C:\> @('Mirë','Kurrë') | Out-LongestCommonSuffix

rë

.EXAMPLE

PS C:\> @('Mela','Ela') | Out-LongestCommonSuffix

ela

.EXAMPLE

PS C:\> @('CreateAccessKey','DeleteAccessKey','UpdateAccessKey') | Out-LongestCommonSuffix

teAccessKey

.EXAMPLE

PS C:\> @('JsonIsThis','JSONIsThis') | Out-LongestCommonSuffix -CaseSensitive

IsThis

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
        [System.String[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $CaseSensitive
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to $inputObjectArr ArrayList.
            $inputObjectArr.AddRange($InputObject)
        }
        else
        {
            # Add single -InputObject object to $inputObjectArr ArrayList.
            $inputObjectArr.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # Cast ArrayList of input objects assembled above to an array of strings.
        $inputObjectArr = [System.String[]] $inputObjectArr

        # Reverse order of all input objects to more easily calculate longest common suffix.
        # Order will be reversed at end of function.
        $inputObjectArr = $inputObjectArr.ForEach( { -join$_[($_.Length - 1)..0] } )

        # Retain copy of first input object so casing of returned longest common suffix will
        # match first input object, especially if user input -CaseSensitive switch parameter
        # is defined causing all input objects to be converted to lowercase below.
        $firstInputObject = $inputObjectArr | Select-Object -First 1

        # Convert all input objects to lowercase if user input -CaseSensitive switch parameter is defined.
        if (-not $PSBoundParameters['CaseSensitive'].IsPresent)
        {
            $inputObjectArr = $inputObjectArr.ForEach( { $_.ToLower() } )
        }

        $longestCommonSuffix = [System.String] $null
        $index = -1
        while ($true)
        {
            $index++

            # Extract character at current index from all input objects.
            $indexCharArr = $inputObjectArr.ForEach( { $_[$index] } ).Where( { $_ } )

            # Break if reached end of any input object.
            if ($indexCharArr.Count -ne $inputObjectArr.Count)
            {
                break
            }

            # Calculate case-sensitive unique list of extracted characters at current index.
            $indexCharArrUniq = $indexCharArr | Sort-Object -Unique -CaseSensitive

            # Break if any differing character(s) found at current index.
            if ($indexCharArrUniq.Count -ne 1)
            {
                break
            }

            # Append current extracted character to longest common suffix string,
            # giving preference to original casing in first input object.
            $longestCommonSuffix += $firstInputObject[$index]
        }

        # Re-reverse order of final longest common suffix since calculated right-to-left.
        $longestCommonSuffix = $longestCommonSuffix.Length -gt 0 ? -join$longestCommonSuffix[($longestCommonSuffix.Length - 1)..0] : $null

        # Return final result.
        $longestCommonSuffix
    }
}