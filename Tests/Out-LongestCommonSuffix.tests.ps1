BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Out-LongestCommonSuffix' -Tag 'Out-LongestCommonSuffix' {
    Context 'extracting longest common suffix from input string' -Tag 'helper' {
        It 'should return longest common suffix' {
            Out-LongestCommonSuffix -InputObject @('Mela','Ela') | Should -BeExactly 'ela'
        }

        It 'should return longest common suffix (via pipeline)' {
            @('Mela','Ela') | Out-LongestCommonSuffix | Should -BeExactly 'ela'
        }

        It 'should return longest common suffix (via pipeline)' {
            @('shumë','mirë') | Out-LongestCommonSuffix | Should -BeExactly 'ë'
        }

        It 'should return longest common suffix with different casing (via pipeline)' {
            @('JsonIsThis','JSONIsThis') | Out-LongestCommonSuffix | Should -BeExactly 'JsonIsThis'
        }

        It 'should return longest common case-sensitive suffix with different casing (via pipeline)' {
            @('JsonIsThis','JSONIsThis') | Out-LongestCommonSuffix -CaseSensitive | Should -BeExactly 'IsThis'
        }
    }
}