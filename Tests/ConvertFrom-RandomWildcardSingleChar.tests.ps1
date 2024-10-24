BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertFrom-RandomWildcardSingleChar' -Tag 'ConvertFrom-RandomWildcardSingleChar' {
    Context 'removing single-character wildcard obfuscation from Action string' -Tag 'helper' {
        It 'should return Action string with single-character wildcard obfuscation completely removed' {
            $randomWildcardDeobfuscatedStr = 'iam:Cr??teAcce??Key' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 100
            $randomWildcardDeobfuscatedStr | Should -BeExactly 'iam:CreateAccessKey'
        }

        It 'should return Action string with single-character wildcard obfuscation partially removed' {
            $randomWildcardDeobfuscatedStr = 'iam:Cr??teAcce??Key' | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent 50
            $randomWildcardDeobfuscatedStrMatch = @('iam:CreateAccessKey') -ilike $randomWildcardDeobfuscatedStr
            $randomWildcardDeobfuscatedStrMatch | Should -BeExactly 'iam:CreateAccessKey'
        }

        It 'should return Action string with single-character wildcard obfuscation partially removed (batch testing)' {
            $obfuscatedActionStr = 'iam:?r??teA???ssKe?'
            $actionsOrig = (Get-AwsAction -Name $obfuscatedActionStr).Action

            $testCount = 50
            $testResArrGrouped = @(1..$testCount).ForEach(
            {
                $randomWildcardDeobfuscatedStr = $obfuscatedActionStr | ConvertFrom-RandomWildcardSingleChar -RandomCharPercent (Get-Random -InputObject @(25,50,75,100))
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