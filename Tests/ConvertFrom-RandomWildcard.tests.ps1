BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertFrom-RandomWildcard' -Tag 'ConvertFrom-RandomWildcard' {
    Context 'removing wildcard obfuscation from Action string' -Tag 'helper' {
        It 'should return Action string with wildcard obfuscation completely removed' {
            $randomWildcardDeobfuscatedStr = 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 10
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:CreateAccessKey'
        }

        It 'should return Action string with wildcard obfuscation partially removed from adjacent wildcards' {
            $randomWildcardDeobfuscatedStr = 'iam:C***teA**y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -Type Adjacent
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:C*teA*y'
        }

        It 'should return Action string with wildcard obfuscation partially removed from prefixes' {
            $randomWildcardDeobfuscatedStr = 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Type Prefix
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:Cre*teAcc*y'
        }

        It 'should return Action string with wildcard obfuscation partially removed from suffixes' {
            $randomWildcardDeobfuscatedStr = 'iam:C*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Type Suffix
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:C*eateA*Key'
        }

        It 'should return Action string with wildcard obfuscation partially removed' {
            $randomWildcardDeobfuscatedStr = 'iam:*teA*y' | ConvertFrom-RandomWildcard -RandomCharPercent 100 -RandomLength 10
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:*teA*ss*y'
        }

        It 'should return Action string with wildcard obfuscation partially removed (batch testing)' {
            $obfuscatedActionStr = 'iam:*teA**ey'
            $actionsOrig = (Get-AwsAction -Name $obfuscatedActionStr).Action

            $testCount = 50
            $testResArrGrouped = @(1..$testCount).ForEach(
            {
                $randomWildcardDeobfuscatedStr = $obfuscatedActionStr | ConvertFrom-RandomWildcard -RandomCharPercent (Get-Random -InputObject @(25,50,75,100))
                $actions = (Get-AwsAction -Name $randomWildcardDeobfuscatedStr).Action
                [PSCustomObject] @{
                    randomWildcardDeobfuscatedStr = $randomWildcardDeobfuscatedStr
                    actions = $actions
                }
            }) | Group-Object actionCount,actions

            ($testResArrGrouped | Measure-Object).Count | Should -BeExactly 1
            $testResArrGrouped[0].Count | Should -BeExactly $testCount
            (($testResArrGrouped[0].Group | Get-Random).actions -join ',') | Should -BeExactly ($actionsOrig -join ',')
        }
    }
}