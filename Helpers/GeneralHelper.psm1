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



function Confirm-FilterEligibility # 2024-09-29 COMPLETED 100% AND TESTED, COMMENTED, UNIT TEST 100%
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Confirm-FilterEligibility
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Confirm-FilterEligibility performs Filter* eligibility checks for input JSON string (in JsonTokenEnriched format).

.PARAMETER InputObject

Specifies JSON string (in JsonTokenEnriched format) for which to perform Filter* eligibility checks.

.PARAMETER Filter

(Optional) Specifies regular expression(s) for which to perform eligibility checks against input JsonTokenEnriched object based on matching node content.

.PARAMETER FilterDecoded

(Optional) Specifies regular expression(s) for which to perform eligibility checks against input JsonTokenEnriched object based on matching decoded node content.

.PARAMETER FilterPath

(Optional) Specifies regular expression(s) for which to perform eligibility checks against input JsonTokenEnriched object based on matching JSON path content.

.PARAMETER FilterPathDecoded

(Optional) Specifies regular expression(s) for which to perform eligibility checks against input JsonTokenEnriched object based on matching decoded JSON path content.

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
        [SkyScalpel.JsonTokenEnriched]
        $InputObject,

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
        $FilterPathDecoded
    )

    # Set boolean for generic eligibility.
    $isEligible = $true
 
    # Perform Filter* eligibility checks for input JSON string (in JsonTokenEnriched format)
    # to potentially override above eligibility.
    if (
        $Filter -and
        ($contentNormalized = $InputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $InputObject.Content.Substring(1,$InputObject.Content.Length - 2) : $InputObject.Content) -and
        -not @($InputObject.Content,$contentNormalized).ForEach( { [regex]::Matches($_,$Filter,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Where( { $_.Success } ) } ).Count -gt 0
    )
    {
        # Override eligibility if optional user input -Filter parameter is defined but
        # does not match current JsonToken content.
        $isEligible = $false
    }
    elseif (
        $FilterDecoded -and
        ($contentDecodedNormalized = $InputObject.Format -eq [SkyScalpel.JsonTokenFormat]::String ? $InputObject.ContentDecoded.Substring(1,$InputObject.ContentDecoded.Length - 2) : $InputObject.ContentDecoded) -and
        -not @($InputObject.ContentDecoded,$contentDecodedNormalized).ForEach( { [regex]::Matches($_,$FilterDecoded,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Where( { $_.Success } ) } ).Count -gt 0
    )
    {
        # Override eligibility if optional user input -FilterDecoded parameter is defined but
        # does not match current JsonToken decoded content.
        $isEligible = $false
    }
    elseif (
        $FilterPath -and
        -not [regex]::Matches($InputObject.Path.Content,$FilterPath,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Where( { $_.Success } ).Count -gt 0
    )
    {
        # Override eligibility if optional user input -FilterPath parameter is defined but
        # does not match current JsonToken Path content.
        $isEligible = $false
    }
    elseif (
        $FilterPathDecoded -and
        -not [regex]::Matches($InputObject.Path.ContentDecoded,$FilterPathDecoded,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Where( { $_.Success } ).Count -gt 0
    )
    {
        # Override eligibility if optional user input -FilterPathDecoded parameter is defined but
        # does not match current JsonToken decoded Path content.
        $isEligible = $false
    }

    # Return final result.
    return $isEligible
}