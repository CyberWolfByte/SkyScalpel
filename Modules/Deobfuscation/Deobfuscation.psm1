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



function Remove-RandomUnicode
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Remove-RandomUnicode
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertFrom-RandomUnicode
Optional Dependencies: None

.DESCRIPTION

Remove-RandomUnicode randomly substitutes eligible unicode encoded character(s) with equivalent decoded syntax in eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to substitute eligible unicode encoded character(s) with equivalent decoded syntax.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to deobfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER Type

(Optional) Specifies eligible node type(s) to deobfuscate.

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit deobfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude deobfuscation eligibility.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '{"na\u006de":"\u0061bi"}' | Remove-RandomUnicode

{"name":"\u0061bi"}

.EXAMPLE

PS C:\> '{"n\u0061\u006de":"\u0061\u0062i"}' | Remove-RandomUnicode | Remove-RandomUnicode

{"name":"abi"}

.EXAMPLE

PS C:\> '{"t\u0065a\u006d":"p0 Labs","membe\u0072s":[{"nam\u0065":"abi"},{"name":"d\u0062\u006f"}]}' | Remove-RandomUnicode -RandomNodePercent 90 -RandomCharPercent 20 -Target JsonToken -TrackModification | Out-JsonObject

{
  "t\u0065am":"p0 Labs",
  "members":[
    {
      "name":"abi"
    },
    {
      "name":"db\u006f"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"\u0061bi"},{"name":"\u0064b\u006f"}]}' | Remove-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 75 -Type Value -FilterDecoded '^(?!.*ab)' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"\u0061bi"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"t\u0065\u0061m":"p0 Labs","m\u0065mb\u0065rs":[{"name":"abi"},{"name":"dbo"}]}' | Remove-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Name -FilterDecoded 'team|member' -Include 'a','e' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"abi"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"\u0061\u0062\u0069"},{"name":"\u0064\u0062\u006F"}]}' | Remove-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPath '^members\.name$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"abi"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","m\u0065mb\u0065rs":[{"name":"\u0061\u0062\u0069"},{"name":"dbo"}]}' | Remove-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPathDecoded '^members\.name$' -FilterDecoded '^"abi"$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "m\u0065mb\u0065rs":[
    {
      "name":"abi"
    },
    {
      "name":"dbo"
    }
  ]
}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [SkyScalpel.JsonToken[]],
        [SkyScalpel.JsonTokenEnriched[]],
        [SkyScalpel.JsonBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'Name',
            'Value'
        )]
        [System.String[]]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $Filter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPathDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Include,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Char[]]
        $Exclude,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target = [SkyScalpel.JsonFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement
        # (ensured by ConvertTo-JsonObject later in current function).
        $requiredInputObjectTarget = [SkyScalpel.JsonFormat]::JsonTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate
        # hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -in @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-JsonObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-JsonObject -InputObject $InputObject -InputObjectArray $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined
        # in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications
        # in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-JsonObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # If both -Filter and -FilterDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterDecoded by setting -Filter to $null.
        if ($Filter -and $FilterDecoded)
        {
            Write-Warning 'Both -Filter and -FilterDecoded input parameters are defined. Defaulting to -FilterDecoded input parameter.'

            $Filter = $null
        }

        # If both -FilterPath and -FilterPathDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterPathDecoded by setting -FilterPath to $null.
        if ($FilterPath -and $FilterPathDecoded)
        {
            Write-Warning 'Both -FilterPath and -FilterPathDecoded input parameters are defined. Defaulting to -FilterPathDecoded input parameter.'

            $FilterPath = $null
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -notin @([SkyScalpel.JsonTokenType]::Name,[SkyScalpel.JsonTokenType]::Value))
            {
                # Override deobfuscation eligibility if current JsonToken is not a Name or Value type
                # (which are the only eligible JsonToken types for unicode encoding).
                $isEligible = $false
            }
            elseif ($curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and $curInputObject.Format -ne [SkyScalpel.JsonTokenFormat]::String)
            {
                # Override deobfuscation eligibility if current JsonToken is a Value type but not of
                # a String format (e.g. Boolean, Null, Number) since only strings support unicode encoding.
                $isEligible = $false
            }
            elseif ($Type -and $Type -inotcontains $curInputObject.Type)
            {
                # Override deobfuscation eligibility if optional user input -Type parameter is defined but
                # does not contain current JsonToken type.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override deobfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }
            elseif ($curInputObject.ContentParsedList.Where( { $_.Format -eq [SkyScalpel.JsonStringParsedFormat]::Hex } ).Count -eq 0)
            {
                # Override deobfuscation eligibility if current JsonToken does not contain any unicode encoded characters.
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.Content.Substring(1,$curInputObject.Content.Length - 2) : $curInputObject.Content;

                # Apply unicode encoding deobfuscation to current JsonToken.
                $curTokenModified = ConvertFrom-RandomUnicode -InputObject $curInputObject.Content -RandomCharPercent $RandomCharPercent -Include $Include -Exclude $Exclude

                # If modification successfully applied above then update current JsonToken.
                # If optional -TrackModification switch is defined then set extracted JsonToken's
                # Depth property to -1 for modification tracking display purposes.
                if ($curTokenModified -cne $curInputObject.Content)
                {
                    $curInputObject.Content = $curTokenModified

                    # If optional -TrackModification switch is defined then set extracted JsonToken's
                    # Depth property to -1 for modification tracking display purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }

                # Add back single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? '"' + $curInputObject.Content + '"' : $curInputObject.Content;
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Remove-RandomWhitespace
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Remove-RandomWhitespace
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject
Optional Dependencies: None

.DESCRIPTION

Remove-RandomWhitespace randomly removes eligible Whitespace character(s) from JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) from which to remove eligible Whitespace character(s).

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to deobfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER Type

(Optional) Specifies node type(s) after which proceeding Whitespace tokens are eligible to deobfuscate.

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content of preceeding node.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content of preceeding node.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit deobfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude deobfuscation eligibility.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '{  "name"  :  "abi"  }  ' | Remove-RandomWhitespace

{"name" :"abi" }

.EXAMPLE

PS C:\> '{  "name"  :  "abi"  }  ' | Remove-RandomWhitespace | Remove-RandomWhitespace

{"name":"abi"}

.EXAMPLE

PS C:\> '{  "team"  :  "p0 Labs"  ,  "members"  :  [  {  "name"  :  "abi"  }  ,  {  "name"  :  "dbo"  }  ]  }  ' | Remove-RandomWhitespace -RandomNodePercent 90 -RandomCharPercent 75 -Target JsonToken -TrackModification | Out-JsonObject -Format compressed

{ "team"  : "p0 Labs", "members":[{"name":"abi"  } , { "name" :"dbo"}]}

.EXAMPLE

PS C:\> '{  "team"  :  "p0 Labs"  ,  "members"  :  [  {  "name"  :  "abi"  }  ,  {  "name"  :  "dbo"  }  ]  }  ' | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterDecoded '^(?!.*ab)' -Target JsonToken -TrackModification | Out-JsonObject -Format compressed

{"team":"p0 Labs"  ,"members":[{"name":"abi"  },{"name":"dbo"}]}

.EXAMPLE

PS C:\> '{  "team"  :  "p0 Labs"  ,  "members"  :  [  {  "name"  :  "abi"  }  ,  {  "name"  :  "dbo"  }  ]  }  ' | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterPath '^members' -Target JsonToken -TrackModification | Out-JsonObject -Format compressed

{  "team"  :  "p0 Labs"  ,  "members":[{"name":"abi"},{"name":"dbo"}]}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [SkyScalpel.JsonToken[]],
        [SkyScalpel.JsonTokenEnriched[]],
        [SkyScalpel.JsonBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonTokenType[]]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $Filter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPathDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(' ',"`t","`r","`n")]
        [System.Char[]]
        $Include = @(' ',"`t","`r","`n"),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(' ',"`t","`r","`n")]
        [System.Char[]]
        $Exclude,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target = [SkyScalpel.JsonFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement
        # (ensured by ConvertTo-JsonObject later in current function).
        $requiredInputObjectTarget = [SkyScalpel.JsonFormat]::JsonTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate
        # hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -in @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-JsonObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-JsonObject -InputObject $InputObject -InputObjectArray $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined
        # in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications
        # in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-JsonObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # If both -Filter and -FilterDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterDecoded by setting -Filter to $null.
        if ($Filter -and $FilterDecoded)
        {
            Write-Warning 'Both -Filter and -FilterDecoded input parameters are defined. Defaulting to -FilterDecoded input parameter.'

            $Filter = $null
        }

        # If both -FilterPath and -FilterPathDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterPathDecoded by setting -FilterPath to $null.
        if ($FilterPath -and $FilterPathDecoded)
        {
            Write-Warning 'Both -FilterPath and -FilterPathDecoded input parameters are defined. Defaulting to -FilterPathDecoded input parameter.'

            $FilterPath = $null
        }

        # Track previous object for 1-step lookback scenarios.
        $prevInputObject = $null

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [SkyScalpel.JsonTokenType]::Whitespace)
            {
                # Override deobfuscation eligibility if current JsonToken is not a Whitespace type.
                $isEligible = $false
            }
            elseif ($Type -and $Type -inotcontains $curInputObject.TypeBefore)
            {
                # Override deobfuscation eligibility if optional user input -Type parameter is defined
                # but current Whitespace JsonToken does not immediately follow a JsonToken type
                # specified in user input -Type parameter.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $prevInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override deobfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match preceding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Apply unicode encoding deobfuscation to current JsonToken.
                $curTokenModified = -join([System.Char[]] $curInputObject.Content).ForEach(
                {
                    $curChar = $_

                    # Set boolean for generic deobfuscation eligibility.
                    $isEligible = $true

                    # Override above deobfuscation eligibility for specific scenarios.
                    if ($curChar -cin $Exclude)
                    {
                        # Override deobfuscation eligibility for characters defined in user input -Exclude parameter.
                        $isEligible = $false
                    }
                    elseif ($Include -and $curChar -cnotin $Include)
                    {
                        # Override deobfuscation eligibility for characters not defined in user input -Include parameter (if it is explicitly defined).
                        $isEligible = $false
                    }

                    # Set boolean for deobfuscation eligibility based on user input -RandomCharPercent value.
                    $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

                    # Proceed if eligible for deobfuscation.
                    if ($isEligible -and $isRandomCharPercent)
                    {
                        # Update current character.
                        $curChar = $null
                    }

                    # Return current character.
                    $curChar
                } )

                # If modification successfully applied above then update current JsonToken.
                # If optional -TrackModification switch is defined then set extracted JsonToken's
                # Depth property to -1 for modification tracking display purposes.
                if ($curTokenModified -cne $curInputObject.Content)
                {
                    $curInputObject.Content = $curTokenModified

                    # If optional -TrackModification switch is defined then set extracted JsonToken's
                    # Depth property to -1 for modification tracking display purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject

            # Update previous object for 1-step lookback scenarios.
            $prevInputObject = $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Remove-RandomWildcard
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Remove-RandomWildcard
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertFrom-RandomWildcard
Optional Dependencies: None

.DESCRIPTION

Remove-RandomWildcard randomly substitutes eligible wildcard character(s) with plaintext substring(s) common to all matching Action values in eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to substitute eligible wildcard character(s) with plaintext substring(s) common to all matching Action values.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to deobfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER RandomLength

(Optional) Specifies maximum eligible length(s) for each plaintext substring to add back from matching Action value(s).

.PARAMETER Type

(Optional) Specifies eligible type(s) of deobfuscation (e.g. Adjacent, Prefix, Suffix, Substring).

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:***re***a*eUser","iam:**Cr**eat*A***c\u002a\u002aes\u002A\u002asKe**y"],"Resource":"*"}]}' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*e**eUs**","iam:*r*ateAcc*ssK*y"],"Resource":"*"}]}' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:Cr\u002Aa*eUse*","iam:Cr*\u0061*eAccessKey"],"Resource":"*"}]}' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -Target JsonToken -TrackModification | Out-JsonObject

{
  "Version":"2012-10-17",
  "Stat\u0065ment":[
    {
      "Effect":"Allow",
      "Not\u0041ction":[
        "iam:CreateUser",
        "iam:Cre\u0061teAccessKey"
      ],
      "Resource":"*"
    }
  ]
}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["i\u0041m:C\u002aU***er","lambda:Li*Fu*gs","iam:*re*s*y"],"Resource":"*"}]}' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -FilterDecoded '(?i)^iam:' -Target JsonToken -TrackModification | Out-JsonObject

{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":[
        "i\u0041m:CreateUser",
        "lambda:Li*Fu*gs",
        "iam:CreateAccessKey"
      ],
      "Resource":"*"
    }
  ]
}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [SkyScalpel.JsonToken[]],
        [SkyScalpel.JsonTokenEnriched[]],
        [SkyScalpel.JsonBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

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
        $Type = @('Adjacent','Prefix','Suffix','Substring'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $Filter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPathDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target = [SkyScalpel.JsonFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement
        # (ensured by ConvertTo-JsonObject later in current function).
        $requiredInputObjectTarget = [SkyScalpel.JsonFormat]::JsonTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate
        # hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -in @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-JsonObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-JsonObject -InputObject $InputObject -InputObjectArray $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined
        # in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications
        # in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-JsonObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # If both -Filter and -FilterDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterDecoded by setting -Filter to $null.
        if ($Filter -and $FilterDecoded)
        {
            Write-Warning 'Both -Filter and -FilterDecoded input parameters are defined. Defaulting to -FilterDecoded input parameter.'

            $Filter = $null
        }

        # If both -FilterPath and -FilterPathDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterPathDecoded by setting -FilterPath to $null.
        if ($FilterPath -and $FilterPathDecoded)
        {
            Write-Warning 'Both -FilterPath and -FilterPathDecoded input parameters are defined. Defaulting to -FilterPathDecoded input parameter.'

            $FilterPath = $null
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if (
                -not(
                    $curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and
                    $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String -and
                    $curInputObject.Path.ContentDecoded -cin @('Statement.Action','Statement.NotAction') -and
                    $curInputObject.ContentParsedList.Where( { $_.ContentDecoded -ceq '*' } ).Count -gt 0
                )
            )
            {
                # Override deobfuscation eligibility if current JsonToken is not a String format Value token with a decoded
                # Path content of Statement.Action or Statement.NotAction containing 1+ wildcard character(s).
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override deobfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }
            elseif ([SkyScalpel.JsonParser]::TrimOne($curInputObject.ContentDecoded,'"') -ceq '*')
            {
                # Override deobfuscation eligibility if current JsonToken is a single wildcard character ('*').
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.Content.Substring(1,$curInputObject.Content.Length - 2) : $curInputObject.Content;

                # Apply wildcard deobfuscation to current JsonToken.
                $curTokenModified = ConvertFrom-RandomWildcard -InputObject $curInputObject.Content -RandomCharPercent $RandomCharPercent -RandomLength $RandomLength -Type $Type

                # If modification successfully applied above then update current JsonToken.
                # If optional -TrackModification switch is defined then set extracted JsonToken's
                # Depth property to -1 for modification tracking display purposes.
                if ($curTokenModified -cne $curInputObject.Content)
                {
                    $curInputObject.Content = $curTokenModified

                    # If optional -TrackModification switch is defined then set extracted JsonToken's
                    # Depth property to -1 for modification tracking display purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }

                # Add back single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? '"' + $curInputObject.Content + '"' : $curInputObject.Content;
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Remove-RandomWildcardSingleChar
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Remove-RandomWildcardSingleChar
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertFrom-RandomWildcardSingleChar
Optional Dependencies: None

.DESCRIPTION

Remove-RandomWildcardSingleChar randomly substitutes eligible single-character wildcard character(s) with plaintext single-character substring(s) common to all matching Action values in eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to substitute eligible single-character wildcard character(s) with plaintext single-character substring(s) common to all matching Action values.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to deobfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:Creat?U???","iam:C?ea?eA??essKey"],"Resource":"*"}]}' | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C\u003fea??User","iam:\u003Fr?ateAccessKey"],"Resource":"*"}]}' | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:C?\u003f\u003F\u003FeUs?r","iam:Cr??t\u003fAcc?ssKey"],"Resource":"*"}]}' | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Target JsonToken -TrackModification | Out-JsonObject

{
  "Version":"2012-10-17",
  "Stat\u0065ment":[
    {
      "Effect":"Allow",
      "Not\u0041ction":[
        "iam:CreateUser",
        "iam:CreateAccessKey"
      ],
      "Resource":"*"
    }
  ]
}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [SkyScalpel.JsonToken[]],
        [SkyScalpel.JsonTokenEnriched[]],
        [SkyScalpel.JsonBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $Filter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Regex[]]
        $FilterPathDecoded,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target = [SkyScalpel.JsonFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement
        # (ensured by ConvertTo-JsonObject later in current function).
        $requiredInputObjectTarget = [SkyScalpel.JsonFormat]::JsonTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate
        # hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -in @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-JsonObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-JsonObject -InputObject $InputObject -InputObjectArray $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined
        # in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications
        # in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-JsonObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # If both -Filter and -FilterDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterDecoded by setting -Filter to $null.
        if ($Filter -and $FilterDecoded)
        {
            Write-Warning 'Both -Filter and -FilterDecoded input parameters are defined. Defaulting to -FilterDecoded input parameter.'

            $Filter = $null
        }

        # If both -FilterPath and -FilterPathDecoded input parameters are defined then throw warning
        # message and proceed with only using -FilterPathDecoded by setting -FilterPath to $null.
        if ($FilterPath -and $FilterPathDecoded)
        {
            Write-Warning 'Both -FilterPath and -FilterPathDecoded input parameters are defined. Defaulting to -FilterPathDecoded input parameter.'

            $FilterPath = $null
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if (
                -not(
                    $curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and
                    $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String -and
                    $curInputObject.Path.ContentDecoded -cin @('Statement.Action','Statement.NotAction') -and
                    $curInputObject.ContentParsedList.Where( { $_.ContentDecoded -ceq '?' } ).Count -gt 0
                )
            )
            {
                # Override deobfuscation eligibility if current JsonToken is not a String format Value token with a decoded Path
                # content of Statement.Action or Statement.NotAction containing 1+ single-character wildcard character(s).
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override deobfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }
            elseif ([SkyScalpel.JsonParser]::TrimOne($curInputObject.ContentDecoded,'"') -ceq '*')
            {
                # Override deobfuscation eligibility if current JsonToken is a single wildcard character ('*').
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.Content.Substring(1,$curInputObject.Content.Length - 2) : $curInputObject.Content;

                # Apply wildcard deobfuscation to current JsonToken.
                $curTokenModified = ConvertFrom-RandomWildcardSingleChar -InputObject $curInputObject.Content -RandomCharPercent $RandomCharPercent

                # If modification successfully applied above then update current JsonToken.
                # If optional -TrackModification switch is defined then set extracted JsonToken's
                # Depth property to -1 for modification tracking display purposes.
                if ($curTokenModified -cne $curInputObject.Content)
                {
                    $curInputObject.Content = $curTokenModified

                    # If optional -TrackModification switch is defined then set extracted JsonToken's
                    # Depth property to -1 for modification tracking display purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }

                # Add back single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? '"' + $curInputObject.Content + '"' : $curInputObject.Content;
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}