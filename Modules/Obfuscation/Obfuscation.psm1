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



function Add-RandomCase # 2024-01-03 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-RandomCase
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertTo-RandomCase
Optional Dependencies: None

.DESCRIPTION

Add-RandomCase randomly inverts case of eligible character(s) in eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to invert case of eligible character(s).

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible node type(s) to obfuscate.

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomCase

{"nAmE":"abi"}

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomCase | Add-RandomCase

{"nAme":"ABi"}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomCase -RandomNodePercent 90 -RandomCharPercent 20 -Target JsonToken -TrackModification | Out-JsonObject

{
  "TeAM":"P0 Labs",
  "membeRs":[
    {
      "Name":"aBi"
    },
    {
      "NamE":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 75 -Type Value -Filter '^(?!.*ab)' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"abi"
    },
    {
      "name":"DbO"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Name -Filter 'team|member' -Include 'a','e' -Target JsonToken -TrackModification | Out-JsonObject

{
  "tEAm":"p0 Labs",
  "mEmbErs":[
    {
      "name":"abi"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPath '^members\.name$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"ABI"
    },
    {
      "name":"DBO"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","m\u0065mb\u0065rs":[{"name":"\u0061bi"},{"name":"dbo"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPathDecoded '^members\.name$' -FilterDecoded '^"abi"$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "m\u0065mb\u0065rs":[
    {
      "name":"\u0041BI"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListUsers","iam:CreateUser"],"Resource":"*"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 35 -FilterPath '^Statement\.Action$' -Type Value -TrackModification -Target JsonToken | Out-JsonObject

{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":[
        "iAm:LiStUSerS",
        "IaM:CrEaTEUsER"
      ],
      "Resource":"*"
    }
  ]
}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","St\u0061tement":[{"Effect":"Allow","Act\u0069on":["i\u0061m:ListUsers","iam:Cre\u0041teUser"],"Resource":"*"}]}' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 35 -FilterPathDecoded '^Statement\.Action$' -Type Value -TrackModification -Target JsonToken | Out-JsonObject

{
  "Version":"2012-10-17",
  "St\u0061tement":[
    {
      "Effect":"Allow",
      "Act\u0069on":[
        "i\u0041M:LiSTUserS",
        "Iam:crE\u0061tEuseR"
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
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -notin @([SkyScalpel.JsonTokenType]::Name,[SkyScalpel.JsonTokenType]::Value))
            {
                # Override obfuscation eligibility if current JsonToken is not a Name or Value type
                # (which are the only eligible JsonToken types for character case randomization).
                $isEligible = $false
            }
            elseif ($curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and $curInputObject.Format -ne [SkyScalpel.JsonTokenFormat]::String)
            {
                # Override obfuscation eligibility if current JsonToken is a Value type but not of a String
                # format (e.g. Boolean, Null, Number) since only strings support character case randomization.
                $isEligible = $false
            }
            elseif ($Type -and $Type -inotcontains $curInputObject.Type)
            {
                # Override obfuscation eligibility if optional user input -Type parameter is defined but
                # does not contain current JsonToken type.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override obfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.Content.Substring(1,$curInputObject.Content.Length - 2) : $curInputObject.Content;

                # Apply character case randomization obfuscation to current JsonToken.
                $curTokenModified = ConvertTo-RandomCase -InputObject $curInputObject.Content -RandomCharPercent $RandomCharPercent -Include $Include -Exclude $Exclude

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


function Add-RandomUnicode # 2024-01-03 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-RandomUnicode
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertTo-RandomUnicode
Optional Dependencies: None

.DESCRIPTION

Add-RandomUnicode randomly substitutes eligible character(s) with equivalent unicode encoded syntax in eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to substitute eligible character(s) with equivalent unicode encoded syntax.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible node type(s) to obfuscate.

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.PARAMETER Case

(Optional) Specifies case option(s) for potential alpha characters in hex encoded unicode syntax (e.g. \u006a versus \u006A).

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomUnicode

{"na\u006de":"\u0061bi"}

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomUnicode | Add-RandomUnicode

{"n\u0061\u006de":"\u0061\u0062i"}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomUnicode -RandomNodePercent 90 -RandomCharPercent 20 -Target JsonToken -TrackModification | Out-JsonObject

{
  "t\u0065a\u006d":"p0 Labs",
  "membe\u0072s":[
    {
      "nam\u0065":"abi"
    },
    {
      "name":"d\u0062\u006f"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 75 -Type Value -Filter '^(?!.*ab)' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"abi"
    },
    {
      "name":"\u0064b\u006f"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Name -Filter 'team|member' -Include 'a','e' -Target JsonToken -TrackModification | Out-JsonObject

{
  "t\u0065\u0061m":"p0 Labs",
  "m\u0065mb\u0065rs":[
    {
      "name":"abi"
    },
    {
      "name":"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPath '^members\.name$' -Case Upper -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "members":[
    {
      "name":"\u0061\u0062\u0069"
    },
    {
      "name":"\u0064\u0062\u006F"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","m\u0065mb\u0065rs":[{"name":"\u0061bi"},{"name":"dbo"}]}' | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -FilterPathDecoded '^members\.name$' -FilterDecoded '^"abi"$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "m\u0065mb\u0065rs":[
    {
      "name":"\u0061\u0062\u0069"
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
        [ValidateSet('Upper','Lower')]
        [System.String[]]
        $Case = @('Upper','Lower'),

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
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -notin @([SkyScalpel.JsonTokenType]::Name,[SkyScalpel.JsonTokenType]::Value))
            {
                # Override obfuscation eligibility if current JsonToken is not a Name or Value type
                # (which are the only eligible JsonToken types for unicode encoding).
                $isEligible = $false
            }
            elseif ($curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and $curInputObject.Format -ne [SkyScalpel.JsonTokenFormat]::String)
            {
                # Override obfuscation eligibility if current JsonToken is a Value type but not of
                # a String format (e.g. Boolean, Null, Number) since only strings support unicode encoding.
                $isEligible = $false
            }
            elseif ($Type -and $Type -inotcontains $curInputObject.Type)
            {
                # Override obfuscation eligibility if optional user input -Type parameter is defined but
                # does not contain current JsonToken type.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override obfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObject.Content = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.Content.Substring(1,$curInputObject.Content.Length - 2) : $curInputObject.Content;

                # Apply unicode encoding obfuscation to current JsonToken.
                $curTokenModified = ConvertTo-RandomUnicode -InputObject $curInputObject.Content -RandomCharPercent $RandomCharPercent -Include $Include -Exclude $Exclude -Case $Case

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


function Add-RandomWhitespace # 2024-01-11 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-RandomWhitespace
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, New-JsonToken, Add-JsonToken, Edit-JsonToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomWhitespace adds random whitespace to input JSON string after eligible JSON string JsonTokens.

.PARAMETER InputObject

Specifies JSON string (in any input format) into which random whitespace will be added.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to obfuscate.

.PARAMETER RandomLength

(Optional) Specifies eligible length(s) for each random whitespace string.

.PARAMETER Char

(Optional) Specifies eligible whitespace character(s) for generating each random whitespace string.

.PARAMETER Type

(Optional) Specifies eligible node type(s) to obfuscate.

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

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomWhitespace

{ "name"  :"abi" }

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomWhitespace | Add-RandomWhitespace

{  "name" :   "abi"  }

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomWhitespace -RandomNodePercent 100 -Type Name,NameSeparator,EndArray -Char ' ',"`t","`n"

{"team" : 
"p0 Labs","members"
	:	

[{"name"
	
:	"abi"},{"name" :
"dbo"}]	 }

.EXAMPLE

PS C:\> '{"team":"p0 Labs","members":[{"name":"abi"},{"name":"dbo"}]}' | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength @(5..10) -Filter 'Labs|team|name' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team"          :"p0 Labs"          ,
  "members":[
    {
      "name"         :"abi"
    },
    {
      "name"     :"dbo"
    }
  ]
}

.EXAMPLE

PS C:\> '{"team":"p0 Labs","m\u0065mb\u0065rs":[{"name":"\u0061bi"},{"name":"dbo"}]}' | Add-RandomWhitespace -RandomNodePercent 100 -Type Name,NameSeparator,Value -RandomLength @(5..10) -FilterPathDecoded '^members\.name$' -Target JsonToken -TrackModification | Out-JsonObject

{
  "team":"p0 Labs",
  "m\u0065mb\u0065rs":[
    {
      "name"         :         "\u0061bi"     
    },
    {
      "name"      :         "dbo"         
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
        [ValidateRange(1,100)]
        [System.Int16[]]
        $RandomLength = @(1,2,3),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(' ',"`t","`r","`n")]
        [System.Char[]]
        $Char = @(' '),

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
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($Type -and $Type -inotcontains $curInputObject.Type)
            {
                # Override obfuscation eligibility if optional user input -Type parameter is defined but
                # does not contain current JsonToken type.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override obfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Generate random Whitespace JsonToken where eligible character(s) and length are based on
                # user input -Char and -RandomLength parameters, respectively.
                # If optional -TrackModification switch is defined then Whitespace's Depth property value will be
                # set to -1 for modification tracking display purposes.
                $randomWhitespaceLength = Get-Random -InputObject $RandomLength
                $randomWhitespaceStr = -join(Get-Random -InputObject ($Char * $randomWhitespaceLength) -Count $randomWhitespaceLength)
                $randomWhitespaceJsonToken = New-JsonToken -Type Whitespace -Content $randomWhitespaceStr @optionalSwitchParameters

                # Add random Whitespace JsonToken after current eligible JsonToken.
                $curInputObject = @($curInputObject,$randomWhitespaceJsonToken)
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


function Add-RandomWildcard # 2024-01-22 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-RandomWildcard
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertTo-RandomWildcard
Optional Dependencies: None

.DESCRIPTION

Add-RandomWildcard randomly adds or substitutes eligible character(s) in eligible JSON string JsonTokens with wildcard character(s).

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to add or substitute eligible character(s) with wildcard character(s).

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER RandomLength

(Optional) Specifies eligible length(s) for each random wildcard string.

.PARAMETER Format

(Optional) Specifies eligible format(s) for each random wildcard string (e.g. plaintext, unicode or format matching original eligible characters).

.PARAMETER Type

(Optional) Specifies eligible type(s) of obfuscation (e.g. inserting before, after or replacing original eligible characters).

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.PARAMETER RetryCount

(Optional) Specifies number of attempts to generate accurate obfuscated node.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}' | Add-RandomWildcard

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:***re***a*eUser","iam:**Cr**eat*A***c\u002a\u002aes\u002A\u002asKe**y"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}' | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 35 -RandomLength 1 -Format Plaintext -Type Replace -Include 'C','r','e','a','t','e'

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*e**eUs**","iam:*r*ateAcc*ssK*y"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:Cr\u0065ateUser","iam:Cre\u0061teAccessKey"],"Resource":"*"}]}' | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 35 -RandomLength 1 -Format Matching -Type Replace -Include 'C','r','e','a','t','e' -Target JsonToken -TrackModification | Out-JsonObject

{
  "Version":"2012-10-17",
  "Stat\u0065ment":[
    {
      "Effect":"Allow",
      "Not\u0041ction":[
        "iam:Cr\u002Aa*eUse*",
        "iam:Cr*\u0061*eAccessKey"
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
        [ValidateRange(1,10)]
        [System.Int16]
        $RetryCount = 3,

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
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if (
                -not(
                    $curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and
                    $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String -and
                    $curInputObject.Path.ContentDecoded -cin @('Statement.Action','Statement.NotAction')
                )
            )
            {
                # Override obfuscation eligibility if current JsonToken is not a String format Value token
                # with a decoded Path content of Statement.Action or Statement.NotAction.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override obfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }
            elseif ([SkyScalpel.JsonParser]::TrimOne($curInputObject.ContentDecoded,'"') -ceq '*')
            {
                # Override obfuscation eligibility if current JsonToken is a single wildcard character ('*').
                $isEligible = $false
            }
            elseif (-not$curInputObject.ContentDecoded.Contains(':'))
            {
                # Override obfuscation eligibility if current JsonToken does not contain a colon character (':').
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObjectTrimmedContentParsedList = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? ($curInputObject.ContentParsedList | Select-Object -Skip 1 | Select-Object -SkipLast 1) : $curInputObject.ContentParsedList

                # Calculate index of colon character separating ServiceName and EventName in Action/NotAction context.
                $colonIndex = $curInputObjectTrimmedContentParsedList.ContentDecoded.IndexOf(':')

                # Create temporary Action object to store arrays of parsed JsonToken string character objects
                # delineated by value format in Action/NotAction context.
                $actionObj = [PSCustomObject] @{
                    BeginQuote  = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.ContentParsedList[0] : $null
                    ServiceName = $curInputObjectTrimmedContentParsedList | Select-Object -First $colonIndex
                    Colon       = $curInputObjectTrimmedContentParsedList[$colonIndex]
                    EventName   = $curInputObjectTrimmedContentParsedList | Select-Object -Skip ($colonIndex + 1)
                    EndQuote    = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.ContentParsedList[-1] : $null
                }

                # Retrieve normalized list of Action value(s) for original Action value.
                $actionList = (Get-AwsAction -Name $curInputObject.Content).Action

                # Attempt -RetryCount attempts for accurately obfuscating original Action value.
                # If no accurate obfuscated Action is generated after -RetryCount attempts in below for loop
                # then do not update original Action value.
                for ($i = 0; $i -lt $RetryCount; $i++)
                {
                    # Apply wildcard character obfuscation to EventName extracted from current JsonToken.
                    $eventNameModified = ConvertTo-RandomWildcard -InputObject (-join$actionObj.EventName.Content) -RandomCharPercent $RandomCharPercent -RandomLength $RandomLength -Type $Type -Format $Format -Include $Include -Exclude $Exclude

                    # Merge obfuscated EventName above back into remainder of modified current JsonToken.
                    $curTokenModified = -join@(
                        $actionObj.BeginQuote.Content
                        $actionObj.ServiceName.Content
                        $actionObj.Colon.Content
                        $eventNameModified
                        $actionObj.EndQuote.Content
                    )

                    # If no obfuscation occurred then continue to next loop iteration.
                    if ($curInputObject.Content -ceq $curTokenModified)
                    {
                        continue
                    }

                    # Retrieve normalized list of Action value(s) for modified Action value.
                    $actionListModified = (Get-AwsAction -Name $curTokenModified).Action

                    # Confirm if modified Action value is accurate (i.e. returns the same list of
                    # normalized Action values as the original Action value).
                    if (
                        ($actionList.Count -eq 0 -and $actionListModified.Count -eq 0) -or
                        ($actionList -and $actionListModified -and -not(Compare-Object -ReferenceObject $actionList -DifferenceObject $actionListModified))
                    )
                    {
                        # Current modified Action value is accurate.
                        # Break out of current for loop since no more iterations needed.
                        break
                    }

                    # Reset modified Action value to original value.
                    $curTokenModified = $curInputObject.Content
                }

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
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Add-RandomWildcardSingleChar # 2024-09-29 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Add-RandomWildcardSingleChar
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Confirm-FilterEligibility, Format-JsonObject, ConvertTo-RandomWildcardSingleChar
Optional Dependencies: None

.DESCRIPTION

Add-RandomWildcardSingleChar randomly substitutes eligible character(s) in eligible JSON string JsonTokens with single-character wildcard character(s).

.PARAMETER InputObject

Specifies JSON string (in any input format) in which to substitute eligible character(s) with single-character wildcard character(s).

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Format

(Optional) Specifies eligible format(s) for each random single-character wildcard string (e.g. plaintext, unicode or format matching original eligible characters).

.PARAMETER Filter

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) to filter eligible nodes based on matching decoded JSON path content.

.PARAMETER Include

(Optional) Specifies character(s) for which to limit obfuscation inclusion eligibility.

.PARAMETER Exclude

(Optional) Specifies character(s) for which to exclude obfuscation eligibility.

.PARAMETER RetryCount

(Optional) Specifies number of attempts to generate accurate obfuscated node.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}' | Add-RandomWildcardSingleChar -Format Plaintext

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:Creat?U???","iam:C?ea?eA??essKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}' | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 35 -Include 'C','r','e','a','t','e'

{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C\u003fea??User","iam:\u003Fr?ateAccessKey"],"Resource":"*"}]}

.EXAMPLE

PS C:\> '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:Cr\u0065ateUser","iam:Cre\u0061teAccessKey"],"Resource":"*"}]}' | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 35 -Include 'C','r','e','a','t','e' -Target JsonToken -TrackModification | Out-JsonObject

{
  "Version":"2012-10-17",
  "Stat\u0065ment":[
    {
      "Effect":"Allow",
      "Not\u0041ction":[
        "iam:?r\u0065ateUs\u003fr",
        "iam:Cr??teAccessK?y"
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
        [ValidateSet(
            'Plaintext',
            'Unicode',
            'Matching'
        )]
        [System.String[]]
        $Format = @('Plaintext','Unicode','Matching'),

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
        [ValidateRange(1,10)]
        [System.Int16]
        $RetryCount = 3,

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
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if (
                -not(
                    $curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Value -and
                    $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String -and
                    $curInputObject.Path.ContentDecoded -cin @('Statement.Action','Statement.NotAction')
                )
            )
            {
                # Override obfuscation eligibility if current JsonToken is not a String format Value token
                # with a decoded Path content of Statement.Action or Statement.NotAction.
                $isEligible = $false
            }
            elseif (-not(Confirm-FilterEligibility -InputObject $curInputObject -Filter $Filter -FilterDecoded $FilterDecoded -FilterPath $FilterPath -FilterPathDecoded $FilterPathDecoded))
            {
                # Override obfuscation eligibility if any optional user input -Filter* parameters are defined but
                # do not match corresponding JsonToken content, decoded content, Path content or decoded Path content.
                $isEligible = $false
            }
            elseif ([SkyScalpel.JsonParser]::TrimOne($curInputObject.ContentDecoded,'"') -ceq '*')
            {
                # Override obfuscation eligibility if current JsonToken is a single wildcard character ('*').
                $isEligible = $false
            }
            elseif (-not$curInputObject.ContentDecoded.Contains(':'))
            {
                # Override obfuscation eligibility if current JsonToken does not contain a colon character (':').
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Trim single pair of encapsulating double quotes if current JsonToken is a String format.
                $curInputObjectTrimmedContentParsedList = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? ($curInputObject.ContentParsedList | Select-Object -Skip 1 | Select-Object -SkipLast 1) : $curInputObject.ContentParsedList

                # Calculate index of colon character separating ServiceName and EventName in Action/NotAction context.
                $colonIndex = $curInputObjectTrimmedContentParsedList.ContentDecoded.IndexOf(':')

                # Create temporary Action object to store arrays of parsed JsonToken string character objects
                # delineated by value format in Action/NotAction context.
                $actionObj = [PSCustomObject] @{
                    BeginQuote  = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.ContentParsedList[0] : $null
                    ServiceName = $curInputObjectTrimmedContentParsedList | Select-Object -First $colonIndex
                    Colon       = $curInputObjectTrimmedContentParsedList[$colonIndex]
                    EventName   = $curInputObjectTrimmedContentParsedList | Select-Object -Skip ($colonIndex + 1)
                    EndQuote    = $curInputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $curInputObject.ContentParsedList[-1] : $null
                }

                # Retrieve normalized list of Action value(s) for original Action value.
                $actionList = (Get-AwsAction -Name $curInputObject.Content).Action

                # Attempt -RetryCount attempts for accurately obfuscating original Action value.
                # If no accurate obfuscated Action is generated after -RetryCount attempts in below for loop
                # then do not update original Action value.
                for ($i = 0; $i -lt $RetryCount; $i++)
                {
                    # Apply single-character wildcard character obfuscation to EventName extracted from current JsonToken.
                    $eventNameModified = ConvertTo-RandomWildcardSingleChar -InputObject (-join$actionObj.EventName.Content) -RandomCharPercent $RandomCharPercent -Format $Format -Include $Include -Exclude $Exclude

                    # Merge obfuscated EventName above back into remainder of modified current JsonToken.
                    $curTokenModified = -join@(
                        $actionObj.BeginQuote.Content
                        $actionObj.ServiceName.Content
                        $actionObj.Colon.Content
                        $eventNameModified
                        $actionObj.EndQuote.Content
                    )

                    # If no obfuscation occurred then continue to next loop iteration.
                    if ($curInputObject.Content -ceq $curTokenModified)
                    {
                        continue
                    }

                    # Retrieve normalized list of Action value(s) for modified Action value.
                    $actionListModified = (Get-AwsAction -Name $curTokenModified).Action

                    # Confirm if modified Action value is accurate (i.e. returns the same list of
                    # normalized Action values as the original Action value).
                    if (
                        ($actionList.Count -eq 0 -and $actionListModified.Count -eq 0) -or
                        ($actionList -and $actionListModified -and -not(Compare-Object -ReferenceObject $actionList -DifferenceObject $actionListModified))
                    )
                    {
                        # Current modified Action value is accurate.
                        # Break out of current for loop since no more iterations needed.
                        break
                    }

                    # Reset modified Action value to original value.
                    $curTokenModified = $curInputObject.Content
                }

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
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-JsonObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}