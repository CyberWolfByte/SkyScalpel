#
# Module manifest for module 'SkyScalpel'
#
# Generated by: Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)
#
# Generated on: 10/22/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'SkyScalpel.psm1'

# Version number of this module.
ModuleVersion = '1.1'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '20080217-ab11-db00-1337-133337c0ffee'

# Author of this module
Author = 'Abian Morina, aka Abi (@AbianMorina) & Daniel Bohannon, aka DBO (@danielhbohannon)'

# Company or vendor of this module
CompanyName = 'Permiso Security'

# Copyright statement for this module
Copyright = 'Apache License, Version 2.0'

# Description of the functionality provided by this module
Description = 'SkyScalpel is a framework for JSON and AWS Policy parsing, obfuscation, deobfuscation and detection.'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '7.1.0'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @(
    'Helpers\AWSHelper.psm1',
    'Helpers\GeneralHelper.psm1',
    'Helpers\JSONHelper.psm1',
    'Modules\Deobfuscation\Deobfuscation.psm1',
    'Modules\Deobfuscation\DeobfuscationHelper.psm1',
    'Modules\Obfuscation\Obfuscation.psm1',
    'Modules\Obfuscation\ObfuscationHelper.psm1',
    'Modules\Detection\DetectionHelper.psm1',
    'Modules\UI\Invoke-SkyScalpelMenu.psm1'
)

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    # AWS helper functions
    'Get-AwsAction',
    'Get-AwsActionListOnline',
    #
    # General helper functions
    'Confirm-FilterEligibility',
    #
    # JSON Object Conversion helper functions
    'ConvertTo-JsonParsedValue',
    'New-JsonToken',
    'Join-JsonObject',
    'Expand-JsonObject',
    'ConvertTo-JsonObject',
    'Format-JsonObject',
    'Out-JsonObject',
    #
    # Deobfuscation functions
    'Remove-RandomUnicode',
    'Remove-RandomWhitespace',
    'Remove-RandomWildcard',
    'Remove-RandomWildcardSingleChar',
    #
    # Deofuscation helper functions
    'ConvertFrom-RandomUnicode',
    'ConvertFrom-RandomWildcard',
    'ConvertFrom-RandomWildcardSingleChar',
    'Out-LongestCommonPrefix',
    'Out-LongestCommonSubstring',
    'Out-LongestCommonSuffix',
    #
    # Detection functions
    'Find-Evil',
	'Out-EvilSummary',
	'Show-EvilSummary',
    #
    # Obfuscation functions
    'Add-RandomCase',
    'Add-RandomUnicode',
    'Add-RandomWhitespace',
    'Add-RandomWildcard',
    'Add-RandomWildcardSingleChar',
    #
    # Obfuscation helper functions
    'ConvertTo-RandomCase',
    'ConvertTo-RandomUnicode',
    'ConvertTo-RandomWildcard',
    'ConvertTo-RandomWildcardSingleChar',
    #
    # UI functions
    'Invoke-SkyScalpel',
	'Show-Menu',
	'Show-OptionsMenu',
	'Show-HelpMenu',
	'Show-Tutorial',
	'Split-Command',
	'Show-AsciiArt',
	'New-ObfuscationContainer',
	'Add-ObfuscationLayer',
	'Remove-ObfuscationLayer',
	'Get-FunctionInfo'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @(
    'Helpers\AWSHelper.psm1',
    'Helpers\GeneralHelper.psm1',
    'Helpers\JSONHelper.psm1',
    'Modules\Deobfuscation\Deobfuscation.psm1',
    'Modules\Deobfuscation\DeobfuscationHelper.psm1',
    'Modules\Obfuscation\Obfuscation.psm1',
    'Modules\Obfuscation\ObfuscationHelper.psm1',
    'Modules\Detection\DetectionHelper.psm1',
    'Modules\UI\Invoke-SkyScalpelMenu.psm1'
)

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}