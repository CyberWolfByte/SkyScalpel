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



function Get-AwsAction
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Get-AwsAction
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-AwsAction returns AWS Action context object(s) that match input name(s). AWS Actions scraped and parsed from https://awspolicygen.s3.amazonaws.com/js/policies.js

.PARAMETER Name

Specifies AWS Action name(s) for which to retrieve corresponding AwsAction object(s).

.EXAMPLE

PS C:\> Get-AwsAction -Name kms:Create*,ec2:Run*

ServicePrefix Action
------------- ------
kms           kms:CreateAlias
kms           kms:CreateCustomKeyStore
kms           kms:CreateGrant
kms           kms:CreateKey
ec2           ec2:RunInstances
ec2           ec2:RunScheduledInstances

.EXAMPLE

PS C:\> Get-AwsAction -Name iam:????teAccessKey

ServicePrefix Action
------------- ------
iam           iam:CreateAccessKey
iam           iam:DeleteAccessKey
iam           iam:UpdateAccessKey

.EXAMPLE

PS C:\> Get-AwsAction -Name iam:????te*Key

ServicePrefix Action
------------- ------
iam           iam:CreateAccessKey
iam           iam:DeleteAccessKey
iam           iam:DeleteCloudFrontPublicKey
iam           iam:DeleteSSHPublicKey
iam           iam:UpdateAccessKey
iam           iam:UpdateCloudFrontPublicKey
iam           iam:UpdateSSHPublicKey

.EXAMPLE

PS C:\> Get-AwsAction -Name iam:\u003F???te\u002aKey

ServicePrefix Action
------------- ------
iam           iam:CreateAccessKey
iam           iam:DeleteAccessKey
iam           iam:DeleteCloudFrontPublicKey
iam           iam:DeleteSSHPublicKey
iam           iam:UpdateAccessKey
iam           iam:UpdateCloudFrontPublicKey
iam           iam:UpdateSSHPublicKey

.EXAMPLE

PS C:\> '"iAm:p*S****e"' | Get-AwsAction

ServicePrefix Action
------------- ------
iam           iam:PassRole

.EXAMPLE

PS C:\> '\u0069\u0041\u006d\u003a\u0063\u0052\u002a\u0065\u0079' | Get-AwsAction

ServicePrefix Action
------------- ------
iam           iam:CreateAccessKey

.EXAMPLE

PS C:\> Get-AwsAction -Name * | Group-Object ServicePrefix | Where-Object { $_.Count -gt 200 } | Select-Object Count,Name

Count Name
----- ----
  309 chime
  247 connect
  631 ec2
  226 glue
  266 iot
  345 sagemaker

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>

    [OutputType([SkyScalpel.AwsAction[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ArgumentCompleter(
            {
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Retrieve all AWS Action string values from list.
                $awsActionStrArr = [SkyScalpel.JsonParser]::awsActionList.Action

                # Modify current parameter value (captured at the time the user enters TAB) by prepending and appending
                # wildcard characters if no wildcard character is found.
                $WordToComplete = $WordToComplete.Contains('*') ? $WordToComplete : "*$WordToComplete*"

                # If current parameter substring was single wildcard character then return all AWS Action string values.
                # Otherwise, filter all AWS Actions with current parameter substring.
                ($WordToComplete -ceq '*') ? $awsActionStrArr : $awsActionStrArr -like $WordToComplete
            }
        )]
        [System.String[]]
        $Name
    )

    begin
    {
        # Create ArrayList to store all pipelined -Name input(s) before beginning final processing.
        $nameArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined -Name input(s) to $nameArr ArrayList before beginning final processing.
        if ($Name.Count -gt 1)
        {
            # Add all -Name objects to $nameArr ArrayList.
            $nameArr.AddRange($Name)
        }
        else
        {
            # Add single -Name object to $nameArr ArrayList.
            $nameArr.Add($Name) | Out-Null
        }
    }

    end
    {
        # Iterate over each input name stored in $nameArr ArrayList.
        @(foreach ($curName in $nameArr)
        {
            # Return AWS Action context object(s) that match current user input name.
            [SkyScalpel.JsonParser]::GetAwsAction($curName)
        })
    }
}


function Get-AwsActionListOnline
{
<#
.SYNOPSIS

SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.

SkyScalpel Function: Split-JsonParsedValue
Author: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-AwsActionListOnline retrieves current list of AWS Actions scraped and parsed from https://awspolicygen.s3.amazonaws.com/js/policies.js, optionally formatted in C# to manually replace existing awsActionList List in ./CSharp/JsonParser.cs.

.PARAMETER FormatAsCSharpList

(Optional) Specifies extracted list of AWS Actions be formatted in C# to manually replace existing awsActionList List in ./CSharp/JsonParser.cs.

.EXAMPLE

PS C:\> Get-AwsActionListOnline | Select-Object -First 10

ServicePrefix Action
------------- ------
a2c           a2c:GetContainerizationJobDetails
a2c           a2c:GetDeploymentJobDetails
a2c           a2c:StartContainerizationJob
a2c           a2c:StartDeploymentJob
a4b           a4b:ApproveSkill
a4b           a4b:AssociateContactWithAddressBook
a4b           a4b:AssociateDeviceWithNetworkProfile
a4b           a4b:AssociateDeviceWithRoom
a4b           a4b:AssociateSkillGroupWithRoom
a4b           a4b:AssociateSkillWithSkillGroup

.EXAMPLE

PS C:\> Get-AwsActionListOnline | Where-Object { $_.Action.StartsWith('iam:Create') }
ServicePrefix Action
------------- ------
iam           iam:CreateAccessKey
iam           iam:CreateAccountAlias
iam           iam:CreateGroup
iam           iam:CreateInstanceProfile
iam           iam:CreateLoginProfile
iam           iam:CreateOpenIDConnectProvider
iam           iam:CreatePolicy
iam           iam:CreatePolicyVersion
iam           iam:CreateRole
iam           iam:CreateSAMLProvider
iam           iam:CreateServiceLinkedRole
iam           iam:CreateServiceSpecificCredential
iam           iam:CreateUser
iam           iam:CreateVirtualMFADevice

.EXAMPLE

PS C:\> Get-AwsActionListOnline -FormatAsCSharpList

        public static readonly List<AwsAction> awsActionList = new List<AwsAction>                              
		{
			new AwsAction("a2c","a2c:GetContainerizationJobDetails"),
			new AwsAction("a2c","a2c:GetDeploymentJobDetails"),
			new AwsAction("a2c","a2c:StartContainerizationJob"),
			<REDACTED>
			new AwsAction("xray","xray:UntagResource"),
			new AwsAction("xray","xray:UpdateGroup"),
			new AwsAction("xray","xray:UpdateSamplingRule"),
		};

.NOTES

This is a Permiso Security project developed by Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://permiso.io
https://github.com/Permiso-io-tools/SkyScalpel
https://twitter.com/AbianMorina
https://twitter.com/danielhbohannon/
#>
    
    [OutputType([SkyScalpel.AwsAction[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $FormatAsCSharpList
    )

    # Download raw AWS actions from JavaScript file.
    $policyListRaw = Invoke-WebRequest -Uri https://awspolicygen.s3.amazonaws.com/js/policies.js

    # Convert embedded JSON containing actions.
    $policyListRawJson = ($policyListRaw.Content -creplace '^app.PolicyEditorConfig=','') | ConvertFrom-Json

    # Extract list of service names in list of actions.
    $serviceNames = ($policyListRawJson.serviceMap | Get-Member -MemberType NoteProperty).Name

    # Iterate over each service name and output SkyScalpel.AwsAction object for each embedded action.
    $actionListArr = @(foreach ($serviceName in $serviceNames)
    {
        $service = $policyListRawJson.serviceMap.$serviceName
        $servicePrefix = $service.StringPrefix
        @(foreach ($action in $service.Actions)
        {
            [SkyScalpel.AwsAction]::new($servicePrefix,"$servicePrefix`:$action")
        })
    }) | Sort-Object ServicePrefix,Action

    # If optional -FormatAsCSharpList switch is defined then updated extracted list of AWS Actions to be
    # formatted in C# to manually replace existing awsActionList List in ./CSharp/JsonParser.cs.
    if ($PSBoundParameters['FormatAsCSharpList'].IsPresent)
    {
        $actionListArr = @(
            "`t`tpublic static readonly List<AwsAction> awsActionList = new List<AwsAction>"
            "`t`t{"
            @(foreach ($action in $actionListArr)
            {
                "`t`t`tnew AwsAction(`"$($action.ServicePrefix)`",`"$($action.Action)`"),"
            })
            "`t`t};"
        ) -join "`n"
    }

    # Return final result.
    $actionListArr
}