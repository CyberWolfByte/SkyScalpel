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



function ConvertTo-JsonParsedValue # 2024-01-03 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST NOT COMPLETED
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-JsonParsedValue
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertTo-JsonParsedValue parses input JSON string into an array of objects specifying each underlying character (even if unicode encoding is present) and its related metadata (format, class, case, etc.).

.PARAMETER InputObject

Specifies JSON string to parse.

.EXAMPLE

PS C:\> 'p0 Labs' | ConvertTo-JsonParsedValue | Format-Table

Content ContentDecoded IsDecoded  Format   Class  Case IsPrintable
------- -------------- ---------  ------   -----  ---- -----------
p       p                  False Default   Alpha Lower        True
0       0                  False Default     Num    NA        True
                           False Default Special    NA        True
L       L                  False Default   Alpha Upper        True
a       a                  False Default   Alpha Lower        True
b       b                  False Default   Alpha Lower        True
s       s                  False Default   Alpha Lower        True

.EXAMPLE

PS C:\> 'Ko\u0073ov\u00EB' | ConvertTo-JsonParsedValue | Format-Table

Content ContentDecoded IsDecoded  Format     Class      Case IsPrintable
------- -------------- ---------  ------     -----      ---- -----------
K       K                  False Default     Alpha     Upper        True
o       o                  False Default     Alpha     Lower        True
\u0073  s                   True     Hex     Alpha     Lower        True
o       o                  False Default     Alpha     Lower        True
v       v                  False Default     Alpha     Lower        True
\u00EB  ë                   True     Hex Undefined Undefined       False

.EXAMPLE

PS C:\> -join('Ko\u0073ov\u00EB' | ConvertTo-JsonParsedValue).ContentDecoded

Kosovë

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([SkyScalpel.JsonStringParsed[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $InputObject
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject.
        foreach ($curInputObject in $InputObject)
        {
            # Parse user input string into array of JsonStringParsed tokens.
            [SkyScalpel.JsonParser]::ParseJsonString($curInputObject)
        }
    }

    end
    {

    }
}


function New-JsonToken # 2024-01-17 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: New-JsonToken
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

New-JsonToken is a simple wrapper function for C# [SkyScalpel.JsonToken]::new() constructor to create new JsonTokens.

.PARAMETER Content

Specifies initial value of new JsonToken's Content property.

.PARAMETER Type

Specifies type of JsonToken to create.

.PARAMETER SubType

Specifies subtype of JsonToken to create.

.PARAMETER Format

Specifies format of JsonToken to create.

.PARAMETER Start

(Optional) Specifies initial value of new JsonToken's Start property.

.PARAMETER Depth

(Optional) Specifies initial value of new JsonToken's Depth property.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies new JsonToken's Depth property value be set to -1 (e.g. for highlighting where modification occurred).

.EXAMPLE

PS C:\> New-JsonToken -Type Name -Content 'Action'

Content   : Action
Type      : Name
SubType   : 
Format    : 
Start     : -1
Length    : 6
Depth     : 0
TokenList : {}

.EXAMPLE

PS C:\> New-JsonToken -Type BeginArray -Content '[' -Start 27 -Depth 3

Content   : [
Type      : BeginArray
SubType   : 
Format    : 
Start     : 27
Length    : 1
Depth     : 3
TokenList : {}

.EXAMPLE

PS C:\> New-JsonToken -Type Value -SubType ArrayElement -Format String -Content 'iam:PassRole' -Start 129 -Depth 4 -Target JsonTokenEnriched

TypeBefore        : 
TypeAfter         : 
Context           : Name: , Value: Content: iam:PassRole, ContentDecoded: iam:PassRole, ContentParsedList: 
                    System.Collections.Generic.List`1[SkyScalpel.JsonStringParsed]
Path              : Depth: -1, Content: , ContentDecoded: , Members: System.Collections.Generic.List`1[SkyScalpel.JsonTokenEnriched]
TokenList         : {}
ContentDecoded    : iam:PassRole
ContentParsedList : {Content: i, ContentDecoded: i, IsDecoded: False, Format: Default, Class: Alpha, Case: Lower, IsPrintable: True, Content: 
                    a, ContentDecoded: a, IsDecoded: False, Format: Default, Class: Alpha, Case: Lower, IsPrintable: True, Content: m, 
                    ContentDecoded: m, IsDecoded: False, Format: Default, Class: Alpha, Case: Lower, IsPrintable: True, Content: :, 
                    ContentDecoded: :, IsDecoded: False, Format: Default, Class: Special, Case: NA, IsPrintable: True…}
Content           : iam:PassRole
Type              : Value
SubType           : ArrayElement
Format            : String
Start             : 129
Length            : 12
Depth             : 4

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [SkyScalpel.JsonToken],
        [SkyScalpel.JsonTokenEnriched]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Content,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [SkyScalpel.JsonTokenType]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonTokenSubType]
        $SubType,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [SkyScalpel.JsonTokenFormat]
        $Format,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int64]
        $Start = -1,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int64]
        $Depth = 0,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('JsonToken','JsonTokenEnriched')]
        [System.String]
        $Target = 'JsonToken',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # If user input -TrackModification switch is defined then set Depth property
    # for new JsonToken to -1 for display tracking purposes.
    if ($PSBoundParameters['TrackModification'].IsPresent)
    {
        # If both -TrackModification and -Depth input parameters are defined then
        # output warning message and proceed with -TrackModification.
        if ($Depth)
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] Both -Depth and -TrackModification input parameters were defined. Defaulting to -TrackModification to set new JsonToken's Depth property to -1 for modification tracking."
        }

        # Set Depth property for new JsonToken to -1 for display tracking purposes.
        $Depth = -1
    }

    # Create JsonToken handling optional user input -SubType and -Format parameters.
    if ($SubType -and $Format)
    {
        $token = [SkyScalpel.JsonToken]::new($Content,$Type,$SubType,$Format,$Start,$Depth)
    }
    elseif ($SubType)
    {
        $token = [SkyScalpel.JsonToken]::new($Content,$Type,$SubType,$Start,$Depth)
    }
    elseif ($Format)
    {
        $token = [SkyScalpel.JsonToken]::new($Content,$Type,$Format,$Start,$Depth)
    }
    else
    {
        $token = [SkyScalpel.JsonToken]::new($Content,$Type,$Start,$Depth)
    }

    # Create and return new JsonToken/JsonTokenEnriched based on user input -Target parameter.
    switch ($Target)
    {
        ([SkyScalpel.JsonFormat]::JsonToken) {
            $token
        }
        ([SkyScalpel.JsonFormat]::JsonTokenEnriched) {
            [SkyScalpel.JsonTokenEnriched]::new($token)
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }
}


function Join-JsonObject # 2024-01-15 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Join-JsonObject
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Join-JsonObject appends input JSON objects (in any format) to input ArrayList while performing any necessary type casting.

.PARAMETER InputObject

Specifies JSON objects (in any input format) to be appended to input ArrayList.

.PARAMETER InputObjectArray

Specifies ArrayList to store input JSON objects (in any input format).

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]
        $InputObjectArray
    )

    begin
    {

    }

    process
    {
        # Add all pipelined input to -InputObjectArray before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to -InputObjectArray ArrayList.
            $InputObjectArray.AddRange($InputObject)
        }
        else
        {
            # For String and JsonBranch scenarios, convert ArrayList or List type to
            # underlying type by assigning -InputObject to its first underlying element.
            if (
                $InputObject.GetType().Name -in @('ArrayList','List`1') -and
                $InputObject[0].GetType().Name -in @('String','JsonBranch')
            )
            {
                $InputObject = $InputObject[0]
            }

            # Throw warning if single -InputObject is not eligible type.
            # This helps detect polluted output streams in new or modified functions.
            $eligibleTypeArr = @('String','JsonToken','JsonTokenEnriched','JsonBranch')
            if ($InputObject.GetType().Name -notin $eligibleTypeArr)
            {
                # Retrieve MyInvocation automatic variable for parent function scope.
                $parentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly

                Write-Warning "Unhandled -InputObject type '$($InputObject.GetType().Name)' found in $($MyInvocation.MyCommand.Name) function called by $($parentFunctionInvocation.MyCommand.Name) function. Eligible -InputObject types include: $($eligibleTypeArr.ForEach( {"'$_'"} ) -join ',')"
            }

            # Add single -InputObject object to -InputObjectArray ArrayList.
            $InputObjectArray.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # If -InputObjectArray is composed of a single object then create temporary ArrayList,
        # initialize with -InputObjectArray content, then overwrite $InputObjectArray variable.
        # This avoids potential re-casting errors in calling function.
        if ($InputObjectArray.Count -eq 1)
        {
            # Create temporary ArrayList to store -InputObjectArray object.
            $inputObjectArrTemp = [System.Collections.ArrayList]::new()

            # Add single -InputObjectArray object to temporary ArrayList.
            $inputObjectArrTemp.Add($InputObjectArray) | Out-Null

            # Overwrite -InputObjectArray with temporary ArrayList.
            $InputObjectArray = $inputObjectArrTemp
        }

        # Return final result.
        $InputObjectArray
    }
}


function Expand-JsonObject # 2024-01-15 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Expand-JsonObject
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject
Optional Dependencies: None

.DESCRIPTION

Expand-JsonObject recursively expands input JSON objects (in any format) into flattened format.

.PARAMETER InputObject

Specifies JSON objects (in any input format) to be recursively expanded into flattened format.

.EXAMPLE

PS C:\> '{"name":"abi"}' | ConvertTo-JsonObject -Target JsonBranch | Expand-JsonObject | Select-Object TypeBefore,TypeAfter,ContentDecoded,Content,Type,SubType,Format,Start,Length,Depth | Format-Table

TypeBefore        TypeAfter ContentDecoded Content          Type SubType      Format Start Length Depth
----------        --------- -------------- -------          ---- -------      ------ ----- ------ -----
                       Name {              {         BeginObject                         0      1     0
BeginObject   NameSeparator "name"         "name"           Name ObjectMember String     1      6     1
Name                  Value :              :       NameSeparator                         7      1     1
NameSeparator     EndObject "abi"          "abi"           Value ObjectMember String     8      5     1
Value                       }              }           EndObject                        13      1     0

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
        $InputObject
    )

    begin
    {
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
        # Iterate over each input object.
        $finalResult = foreach ($curInputObject in $inputObjectArr)
        {
            # Output current object(s) after expanding (where applicable) based on object type.
            switch ($curInputObject.GetType().Name)
            {
                'String' {
                    # Return String as-is.
                    $curInputObject
                }
                'JsonToken' {
                    # Return JsonToken as-is.
                    $curInputObject
                }
                'JsonTokenEnriched' {
                    # Return JsonTokenEnriched as-is.
                    $curInputObject
                }
                'JsonBranch' {
                    # Recursively return all objects in JsonBranch's Branch property.
                    Expand-JsonObject -InputObject $curInputObject.Branch
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }
        }

        # Return final result.
        $finalResult
    }
}


function ConvertTo-JsonObject # 2024-01-15 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100% _____ 2024-01-15 DBO: remove $global:thisErrorStuff try/catch block after finalizing error handling in CSharp parser for invalid JSON
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: ConvertTo-JsonObject
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, Expand-JsonObject, [SkyScalpel.JsonParser] class
Optional Dependencies: None

.DESCRIPTION

ConvertTo-JsonObject converts input JSON to one of many parsed JSON data formats.

.PARAMETER InputObject

Specifies JSON (in any input format) to be converted to one of many parsed JSON data formats.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies 'Depth' property be set to -1 for all JSON tokens created from -InputObject (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"name":"abi"}' | ConvertTo-JsonObject -Target JsonToken | Format-Table

Content          Type SubType      Format Start Length Depth TokenList
-------          ---- -------      ------ ----- ------ ----- ---------
{         BeginObject                         0      1     0 {}
"name"           Name ObjectMember String     1      6     1 {}
:       NameSeparator                         7      1     1 {}
"abi"           Value ObjectMember String     8      5     1 {}
}           EndObject                        13      1     0 {}

.EXAMPLE

PS C:\> '{"name":"abi"}' | ConvertTo-JsonObject -Target JsonBranch | ConvertTo-JsonObject -Target String

{"name":"abi"}

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

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Create ArrayList to store all pipelineed input before beginning final processing.
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
        # Extract base JSON string from $inputObjectArr ArrayList.
        if (($inputObjectArr.Count -eq 1) -and ($inputObjectArr[0].GetType().Name -eq 'String'))
        {
            # If $inputObjectArr ArrayList only contains a single JSON string then no extraction required.
            $jsonStr = $inputObjectArr
        }
        else
        {
            # Extract JSON string by expanding $inputObjectArr ArrayList.
            $jsonStr = -join(Expand-JsonObject -InputObject $inputObjectArr).Content
        }

        # Tokenize extracted base JSON string.
        $jsonStrTokenized = [SkyScalpel.JsonParser]::Tokenize($jsonStr)

        # If user input -TrackModification switch is defined then override Depth value of
        # all JsonTokens to -1.
        # This is used by obfuscation functions to succinctly track any newly added/modified
        # JsonTokens for display purposes.
        if ($PSBoundParameters['TrackModification'].IsPresent)
        {
            # Override all JsonToken Depth values to -1.
            foreach ($token in $jsonStrTokenized)
            {
                $token.Depth = -1

                # If current JsonToken's TokenList contains any nested JsonTokens (e.g. newly
                # added adjacent Whitespace scenario) then override their Depth values to -1.
                foreach ($subToken in $token.TokenList)
                {
                    $subToken.Depth = -1
                }
            }
        }

        # Convert JSON string to appropriate parsed format based on user input -Target value.
        $finalResult = switch ($Target)
        {
            ([SkyScalpel.JsonFormat]::String) {
                [System.String] $jsonStr
            }
            ([SkyScalpel.JsonFormat]::JsonToken) {
                [SkyScalpel.JsonToken[]] $jsonStrTokenized
            }
            ([SkyScalpel.JsonFormat]::JsonTokenEnriched) {
                [SkyScalpel.JsonTokenEnriched[]] [SkyScalpel.JsonParser]::ToTokenEnriched($jsonStrTokenized)
            }
            ([SkyScalpel.JsonFormat]::JsonBranch) {
                [SkyScalpel.JsonBranch] [SkyScalpel.JsonParser]::ToBranch($jsonStrTokenized)
            }
        }

        # Return final result.
        $finalResult
    }
}


function Format-JsonObject # 2024-01-17 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Format-JsonObject
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, ConvertTo-JsonObject, Expand-JsonObject
Optional Dependencies: None

.DESCRIPTION

Format-JsonObject converts input JSON to one of many parsed JSON data formats while optionally maintaining modification tracking.

.PARAMETER InputObject

Specifies JSON (in any input format) to be converted to one of many parsed JSON data formats while optionally maintaining modification tracking.

.PARAMETER Target

(Optional) Specifies target JSON format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified JSON tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '{"name":"abi"}' | Format-JsonObject -Target JsonToken | Format-Table

Content          Type SubType      Format Start Length Depth TokenList
-------          ---- -------      ------ ----- ------ ----- ---------
{         BeginObject                         0      1     0 {}
"name"           Name ObjectMember String     1      6     1 {}
:       NameSeparator                         7      1     1 {}
"abi"           Value ObjectMember String     8      5     1 {}
}           EndObject                        13      1     0 {}

.EXAMPLE

PS C:\> '{"name":"abi"}' | Format-JsonObject -Target JsonBranch | Format-JsonObject -Target String

{"name":"abi"}

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomUnicode -RandomNodePercent 100 -TrackModification -Target JsonToken | Format-JsonObject -TrackModification -Target JsonToken | Select-Object Modified,Depth,Type,Content

Modified Depth          Type Content
-------- -----          ---- -------
             0   BeginObject {
True         1          Name "na\u006De"
             1 NameSeparator :
True         1         Value "\u0061\u0062i"
             0     EndObject }

.EXAMPLE

PS C:\> '{"name":"abi"}' | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -TrackModification -Target JsonTokenEnriched | Format-JsonObject -TrackModification -Target JsonTokenEnriched | Select-Object Modified,Depth,Type,Content

Modified Depth          Type Content
-------- -----          ---- -------
             0   BeginObject {
True         1    Whitespace      
             1          Name "name"
True         1    Whitespace      
             1 NameSeparator :
True         1    Whitespace      
             1         Value "abi"
True         1    Whitespace      
             0     EndObject }
True         0    Whitespace      

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
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [SkyScalpel.JsonFormat]
        $Target,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
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
        # Ensure final result is formatted according to user input -Target value.
        # First ensure input object array is first formatted as an array of JsonTokens.
        # Handle single string scenario separately to preserve potential modification
        # tracking data in non-string input formats.
        if (($inputObjectArr.Count -eq 1) -and ($inputObjectArr[0] -is [System.String]))
        {
            $inputObjectArr = ConvertTo-JsonObject -InputObject $inputObjectArr -Target JsonToken
        }
        else
        {
            $inputObjectArr = Expand-JsonObject -InputObject $inputObjectArr
        }

        # Remove any objects from input object array that contain a null Content property
        # (e.g. via Remove-Random* deobfuscation functions).
        # This avoids issues when iterating over each index in current input object array
        # and re-parsed version below.
        $inputObjectArr = $inputObjectArr.Where( { $_.Content } )

        # Re-parse modified input object array to re-compute properties (e.g. Depth, Start, Length, etc.).
        # Ensure final result is formatted according to user input -Target value.
        $finalResult = ConvertTo-JsonObject -InputObject (-join$inputObjectArr.Content) -Target $Target

        # If user input -TrackModification switch is defined along with eligible -Target value,
        # add Modified property to all tokens modified in current function.
        # This is primarily for display highlighting in Out-JsonObject function.
        if ($PSBoundParameters['TrackModification'].IsPresent)
        {
            # Define -Target values eligible for -TrackModification logic.
            $eligibleTargetArr = @([SkyScalpel.JsonFormat]::JsonToken,[SkyScalpel.JsonFormat]::JsonTokenEnriched)

            # Throw warning if ineligible -Target is defined for use with -TrackModification.
            # Otherwise proceed with -TrackModification logic.
            if ($Target -notin $eligibleTargetArr)
            {
                # Retrieve MyInvocation automatic variable for parent function scope.
                $parentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly

                Write-Warning "Ineligible -Target value '$Target' used in conjunction with -TrackModification switch in $($MyInvocation.MyCommand.Name) function called by $($parentFunctionInvocation.MyCommand.Name) function. Eligible -Target values for use with -TrackModification switch include: $($eligibleTargetArr.ForEach( {"'$_'"} ) -join ',')"
            }
            else
            {
                # Transpose modification tracking from original, pre-converted -InputObject
                # array JsonTokens onto re-parsed $finalResult array.

                # Transpose any nested JsonTokens in Whitespace JsonToken's TokenList property
                # (produced by previous invocation of current function) from original, pre-
                # converted -InputObject array JsonTokens onto re-parsed $finalResult array.
                # This step is necessary if current function is called twice where second invocation
                # would otherwise drop Whitespace TokenList values produced by first invocation.
                for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
                {
                    # If current JsonToken is a Whitespace JsonToken containing adjacent JsonTokens
                    # in its TokenList property then copy from -InputObject array to $finalResult array,
                    # casting TokenList contents to JsonTokenEnriched array if currently different type
                    # (i.e. JsonToken array).
                    if (($inputObjectArr[$i].Type -eq [SkyScalpel.JsonTokenType]::Whitespace) -and $inputObjectArr[$i].TokenList)
                    {
                        # Copy current Whitespace JsonToken's TokenList property contents from -InputObject
                        # array to $finalResult array, evaluating each TokenList object individually to see
                        # if cast to JsonTokenEnriched is needed along with manual re-addition of custom
                        # Modified property since this will be lost during JsonTokenEnriched type cast.
                        $finalResult[$i].TokenList = @(foreach ($curTokenListJsonToken in $inputObjectArr[$i].TokenList)
                        {
                            # If current TokenList adjacent Whitespace JsonToken is not of type JsonTokenEnriched
                            # then cast it to JsonTokenEnriched and manually re-add custom Modified property
                            # since this will be lost during JsonTokenEnriched type cast.
                            if ($curTokenListJsonToken -isnot [SkyScalpel.JsonTokenEnriched])
                            {
                                # Set boolean if current TokenList adjacent Whitespace JsonToken in original,
                                # pre-converted -InputObject array was modified in previous function.
                                # This is denoted by either the Modified property being present or the Depth
                                # property set to -1.
                                $isModified = ($curTokenListJsonToken.Modified -or ($curTokenListJsonToken.Depth -eq -1)) ? $true : $false

                                # Cast current TokenList adjacent Whitespace JsonToken to JsonTokenEnriched.
                                $curTokenListJsonToken = [SkyScalpel.JsonTokenEnriched] $curTokenListJsonToken

                                # If current TokenList adjacent Whitespace JsonToken had Modified property
                                # before type cast then re-add it to converted JsonTokenEnriched result.
                                if ($isModified)
                                {
                                    $curTokenListJsonToken | Add-Member -MemberType NoteProperty -Name 'Modified' -Value $true
                                }
                            }

                            # Return current TokenList adjacent Whitespace JsonToken.
                            $curTokenListJsonToken
                        })
                    }
                }

                # If adjacent Whitespace JsonTokens are present then token count will differ
                # between $inputObjectArr and re-parsed $finalResult.
                # Therefore, while using $i to iterate over $inputObjectArr in below for loop,
                # also use $j to track current index for $finalResult which will not advance
                # multiple times for potential adjacent Whitespace JsonTokens like $i will in
                # inner for loop logic.
                $j = -1

                # Iterate over all objects in original, pre-converted -InputObject array.
                for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
                {
                    # Increment $j index to match each step of for loop definition, though $i will
                    # have additional increments if adjacent Whitespace JsonTokens are detected.
                    $j++

                    # Set boolean if current JsonToken in original, pre-converted -InputObject
                    # array was modified in previous function.
                    # This is denoted by either the Modified property being present or the Depth
                    # property set to -1.
                    $isModified = ($inputObjectArr[$i].Modified -or ($inputObjectArr[$i].Depth -eq -1)) ? $true : $false

                    # If current JsonToken is Whitespace check if adjacent Whitespace JsonTokens
                    # are present in original -InputObject since they will be merged in re-parsed $finalResult.
                    # If present each adjacent Whitespace JsonToken will be extracted and added
                    # to TokenList property of corresponding single Whitespace JsonToken in $finalResult
                    # so modification tracking information can be maintained per JsonToken for display
                    # purposes (e.g. for Out-JsonObject function).
                    if (
                        ($inputObjectArr[$i    ].Type -eq [SkyScalpel.JsonTokenType]::Whitespace) -and
                        ($inputObjectArr[$i + 1].Type -eq [SkyScalpel.JsonTokenType]::Whitespace)
                    )
                    {
                        # Capture all potential adjacent Whitespace JsonTokens as an array.
                        $adjacentJsonTokenWhitespaceArr = @(foreach ($curInputObject in $inputObjectArr[$i..($inputObjectArr.Count - 1)])
                        {
                            # Process next JsonToken if it is a Whitespace JsonToken.
                            if ($curInputObject.Type -eq [SkyScalpel.JsonTokenType]::Whitespace)
                            {
                                # If current adjacent Whitespace JsonToken has a Depth of -1 but does not have a Modified property then add it.
                                if (-not $curInputObject.Modified -and ($curInputObject.Depth -eq -1))
                                {
                                    $curInputObject | Add-Member -MemberType NoteProperty -Name 'Modified' -Value $true
                                }

                                # For proper display purposes have current adjacent Whitespace JsonToken
                                # inherit Depth of re-parsed and merged Whitespace JsonToken in $finalResult.
                                $curInputObject.Depth = $finalResult[$j].Depth

                                # Return current adjacent Whitespace JsonToken.
                                $curInputObject
                            }
                            else
                            {
                                # Break out of foreach loop once first non-Whitespace JsonToken is found.
                                break
                            }
                        })

                        # Increment current for loop's $i index by count of additional adjacent Whitespace
                        # JsonTokens extracted above.
                        $i += $adjacentJsonTokenWhitespaceArr.Count - 1

                        # Store extracted array of adjacent Whitespace JsonTokens in TokenList property
                        # of current merged Whitespace JsonToken in re-parsed $finalResult array.
                        $finalResult[$j].TokenList = $adjacentJsonTokenWhitespaceArr

                        # If user input -Target parameter is JsonTokenEnriched and at least one object
                        # in extracted array of adjacent Whitespace tokens is a JsonToken, manually
                        # re-add Modified property to newly converted JsonTokenEnriched objects.
                        if (($Target -eq [SkyScalpel.JsonFormat]::JsonTokenEnriched) -and $adjacentJsonTokenWhitespaceArr.Where( { $_.GetType().Name -eq 'JsonToken' } ))
                        {
                            # Iterate over array of adjacent Whitespace JsonTokenEnriched objects,
                            # re-adding any Modified properties dropped during automatic type cast.
                            for ($index = 0; $index -lt $finalResult[$j].TokenList.Count; $index++)
                            {
                                # If original JsonToken was modified and current JsonTokenEnriched
                                # does not have Modified property then manually add it.
                                if ($adjacentJsonTokenWhitespaceArr[$index].Modified -and -not $finalResult[$j].TokenList[$index].Modified)
                                {
                                    $finalResult[$j].TokenList[$index] | Add-Member -MemberType NoteProperty -Name 'Modified' -Value $true
                                }
                            }
                        }

                        # If any adjacent Whitespace JsonTokens extracted above are modified then
                        # override $isModified Boolean (set before current if block) to force
                        # addition of Modified property boolean value of $true to newly parsed
                        # final result later in current function.
                        if ($finalResult[$j].TokenList.Modified -and -not $finalResult[$j].Modified)
                        {
                            $isModified = $true
                        }
                    }

                    # If current object in pre-converted -InputObject array was modified then add
                    # Modified property boolean value of $true to newly parsed final result.
                    if ($isModified)
                    {
                        $finalResult[$j] | Add-Member -MemberType NoteProperty -Name 'Modified' -Value $true
                    }
                }
            }
        }

        # Return final result.
        $finalResult
    }
}


function Out-JsonObject # 2024-10-23 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Out-JsonObject
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-JsonObject, Format-JsonObject
Optional Dependencies: None

.DESCRIPTION

Out-JsonObject outputs JSON with token-specific color-coding, optional highlighting and single-line raw, compressed or tree formatting for simplified readability.

.PARAMETER InputObject

Specifies JSON document (in any input format) to format and output.

.PARAMETER Indentation

(Optional) Specifies string to use for indentation, calculated for each line based on JSON document's depth (only applies to -Format 'tree' option).

.PARAMETER ShowWhitespace

(Optional) Specifies that Whitespace be highlighted.

.PARAMETER SkipModificationHighlighting

(Optional) Specifies that any modified tokens in JSON not be highlighted.

.PARAMETER Format

(Optional) Specifies output format for JSON (e.g. single-line 'raw' format, single-line 'compressed' format or multi-line 'tree' format).

.PARAMETER PassThru

(Optional) Specifies that JSON be output to stdout potentially in addition to being output to stdhost.

.PARAMETER Quiet

(Optional) Specifies that JSON not be output to stdhost (e.g. typically used in conjunction with -PassThru).

.EXAMPLE

PS C:\> '{"country":"Kosovë","city":"Gjakova"}' | Out-JsonObject

{
  "country":"Kosovë",
  "city":"Gjakova"
}

.EXAMPLE

PS C:\> '{"country":"Kosovë","city":"Gjakova"}' | Out-JsonObject -Indentation "`t"

{
	"country":"Kosovë",
	"city":"Gjakova"
}

.EXAMPLE

PS C:\> '   {    "country":    "Kosovë"   ,    "city"    :    "Gjakova"    }   ' | Out-JsonObject -Format compressed

{"country":"Kosovë","city":"Gjakova"}

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.Void],
        [System.String]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of JSON formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateScript( { $_ -cmatch '^\s*$' } )]
        [System.String]
        $Indentation = '  ',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ShowWhitespace,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $SkipModificationHighlighting,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('compressed','tree','raw')]
        [System.String]
        $Format = 'tree',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $PassThru,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by Format-JsonObject later in current function).
        $requiredInputObjectTarget = [SkyScalpel.JsonFormat]::JsonToken

        # If user input -SkipModificationHighlighting switch is not defined then add -TrackModification to relevant function invocations in current function.
        # This ensures highlighting is enabled by default in current function.
        $optionalSwitchParameters = @{ }
        if (-not $PSBoundParameters['SkipModificationHighlighting'].IsPresent)
        {
            $optionalSwitchParameters.Add('TrackModification', $true)
        }

        # Define output foreground colors for all JsonToken Type property values and background colors for tracked modification highlighting.
        $colorObj = [PSCustomObject] @{
            Foreground = [PSCustomObject] @{
                Whitespace     = [System.ConsoleColor]::Gray
                BeginObject    = [System.ConsoleColor]::White
                EndObject      = [System.ConsoleColor]::White
                BeginArray     = [System.ConsoleColor]::DarkRed
                EndArray       = [System.ConsoleColor]::DarkRed
                ValueSeparator = [System.ConsoleColor]::DarkYellow
                NameSeparator  = [System.ConsoleColor]::Yellow
                Name           = [System.ConsoleColor]::Magenta
                Value = [PSCustomObject] @{
                    Boolean = [System.ConsoleColor]::Cyan
                    Null    = [System.ConsoleColor]::Cyan
                    Number  = [System.ConsoleColor]::Cyan
                    String  = [System.ConsoleColor]::Green
                }
            }
            Background = [PSCustomObject] @{
                TrackModification = [System.ConsoleColor]::DarkGray
                ShowWhitespace    = [System.ConsoleColor]::DarkYellow
            }
        }

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
        # Format input $inputObjectArr ArrayList according to user input -Target and optional -TrackModification values.
        # In current function -TrackModification is defined as the absence of user input -SkipModificationHighlighting switch parameter so highlighting is enabled by default.
        # For performance purposes, skip re-formatting if input $inputObjectArr ArrayList is already in correct format since current function does not modify user input -InputObject.
        $isCorrectFormat = (($inputObjectArr.ForEach( { $_.GetType().Name } )) | Sort-Object -Unique) -iin @('JsonToken','JsonTokenEnriched')
        if (-not $isCorrectFormat)
        {
            $inputObjectArr = Format-JsonObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget @optionalSwitchParameters
        }

        # Expand any TokenList property values for simpler traversal before outputting.
        # This includes the following two scenarios:
        #   1) A Value JsonToken contains parsed JsonTokens in TokenList property.
        #   2) Adjacent Whitespace scenario where a merged (from re-parsing) Whitespace JsonToken contains original adjacent Whitespace JsonTokens in TokenList property.
        $inputObjectArr = @(foreach ($curToken in $inputObjectArr)
        {
            # Expand TokenList property if present in Value or Whitespace JsonToken.
            if ($curToken.TokenList -and $curToken.Type -in @([SkyScalpel.JsonTokenType]::Value,[SkyScalpel.JsonTokenType]::Whitespace))
            {
                # Expand TokenList property, performing double expansion if TokenList contains Whitespace JsonToken with its TokenList property defined.
                $curToken = $curToken.TokenList.Where( { $_ } ).ForEach(
                {
                    # If current TokenList object is a Whitespace JsonToken that also has its TokenList property defined then further expand nested Whitespace JsonTokens.
                    # Otherwise return current TokenList object as-is.
                    ($_.TokenList -and ($_.Type -eq [SkyScalpel.JsonTokenType]::Whitespace)) ? $_.TokenList : $_
                } )
            }

            # Return current JsonToken.
            $curToken
        })

        # Track current depth of JsonTokens to properly output newline and indention for tree view.
        $curDepth = -1

        # Iterate over each input JsonToken.
        $stdOutForPassThruArr = for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
        {
            $curToken = $inputObjectArr[$i]

            # Skip outputting potential Whitespace JsonTokens if user input Format parameter is 'compressed'.
            if ($Format -eq 'compressed' -and $curToken.Type -eq [SkyScalpel.JsonTokenType]::Whitespace)
            {
                continue
            }

            # Normalize potential carriage return characters ('\r') in Whitespace JsonTokens if user input Format parameter is 'tree'.
            if ($Format -eq 'tree' -and $curToken.Type -eq [SkyScalpel.JsonTokenType]::Whitespace)
            {
                $curToken.Content = $curToken.Content -creplace '\r',' '
            }

            # Output potential newline with current indentation before outputting current JsonToken
            # if user input -Format value of 'tree' is defined and if current non-first JsonToken has change of depth.
            if ($Format -eq 'tree' -and $curToken.Depth -ne $curDepth -and $i -gt 0)
            {
                # If change in depth then output newline with current indentation (unless first JsonToken) and update depth tracker.
                # This should typically only involve EndArray and EndObject JsonTokens.
                if ($curToken.Depth -ne $curDepth)
                {
                    # Define current newline and indentation based on current JsonToken's Depth property.
                    $indentedNewline = "`n$($Indentation * $curToken.Depth)"

                    # Output current newline and indentation to stdhost if user input -Quiet switch is not defined.
                    if (-not$PSBoundParameters['Quiet'].IsPresent)
                    {
                        Write-Host $indentedNewline -NoNewline
                    }

                    # Output current newline and indentation to stdout if user input -PassThru switch is defined.
                    if ($PSBoundParameters['PassThru'].IsPresent)
                    {
                        $indentedNewline
                    }
                }

                # Update depth tracker with current JsonToken's Depth.
                $curDepth = $curToken.Depth
            }

            # Output current JsonToken to stdhost if user input -Quiet switch is not defined.
            if (-not $PSBoundParameters['Quiet'].IsPresent)
            {
                # Retrieve foreground color based on current JsonToken's Type property (and potential Format property).
                $foregroundColor = $curToken.Type -eq [SkyScalpel.JsonTokenType]::Value ? $colorObj.Foreground.($curToken.Type).($curToken.Format) : $colorObj.Foreground.($curToken.Type)

                # Create hashtable to house foreground and potential background color for current JsonToken based on JsonToken type and optional user input parameters.
                # This hashtable will be passed to Write-Host cmdlet via splatting.
                # Add foreground color based on current JsonToken's type according to color-coded definition in current function's Begin block.
                $outputColorParameters = @{ }
                $outputColorParameters.Add('ForegroundColor', $foregroundColor)

                # Set boolean to capture if current JsonToken was modified in last obfuscation function unless user input -SkipModificationHighlighting switch is defined.
                $isHighlightModification = ($curToken.Modified -and -not $PSBoundParameters['SkipModificationHighlighting'].IsPresent) ? $true : $false

                # Set boolean to capture if current JsonToken type is Whitespace and if user input -ShowWhitespace switch is defined.
                $isHighlightWhitespace = (($curToken.Type -eq [SkyScalpel.JsonTokenType]::Whitespace) -and $PSBoundParameters['ShowWhitespace'].IsPresent) ? $true : $false

                # Potentially add background color based on current JsonToken's potential modification and above booleans based on user input switch parameters.
                if ($isHighlightModification)
                {
                    # Add additional background highlighting for JsonToken(s) modified in last obfuscation function if eligible.
                    $outputColorParameters.Add('BackgroundColor', $colorObj.Background.TrackModification)
                }
                elseif ($isHighlightWhitespace)
                {
                    # If user input -ShowWhitespace switch is defined and current JsonToken is Whitespace then output JsonToken with additional background highlighting.
                    # Preference will be given to modification tracking background color highlighting, if eligible.
                    $outputColorParameters.Add('BackgroundColor', $colorObj.Background.ShowWhitespace)
                }

                # If foreground and background colors are both defined for current JsonToken and are the same color then invert the foreground color to avoid JsonToken from being hidden from view.
                if ($outputColorParameters['BackgroundColor'] -eq $outputColorParameters['ForegroundColor'])
                {
                    $outputColorParameters['ForegroundColor'] = $outputColorParameters['ForegroundColor'].ToString().StartsWith('Dark') ? ([System.ConsoleColor] $outputColorParameters['ForegroundColor'].ToString().Replace('Dark','')) : ([System.ConsoleColor] ('Dark' + $outputColorParameters['ForegroundColor']))
                }

                # Output current JsonToken with designated foreground color and optional background highlighting.
                Write-Host $curToken.Content -NoNewline @outputColorParameters
            }

            # Output current JsonToken to stdout if user input -PassThru switch is defined.
            if ($PSBoundParameters['PassThru'].IsPresent)
            {
                $curToken.Content
            }

            # Output potential newline with current indentation after outputting current JsonToken if
            # user input -Format value of 'tree' is defined and if current JsonToken is a ValueSeparator type.
            if ($Format -eq 'tree' -and $curToken.Type -eq [SkyScalpel.JsonTokenType]::ValueSeparator)
            {
                # Define current newline and indentation based on current JsonToken's Depth property.
                $indentedNewline = "`n$($Indentation * $curToken.Depth)"

                # Output current newline and indentation to stdhost if user input -Quiet switch is not defined.
                if (-not$PSBoundParameters['Quiet'].IsPresent)
                {
                    Write-Host $indentedNewline -NoNewline
                }

                # Output current newline and indentation to stdout if user input -PassThru switch is defined.
                if ($PSBoundParameters['PassThru'].IsPresent)
                {
                    $indentedNewline
                }
            }
        }

        # Output final newline.
        Write-Host ''

        # Return final result to stdout if user input -PassThru switch is defined.
        if ($PSBoundParameters['PassThru'].IsPresent)
        {
            -join$stdOutForPassThruArr
        }
    }
}