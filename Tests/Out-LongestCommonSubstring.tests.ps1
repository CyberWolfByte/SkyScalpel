BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Out-LongestCommonSubstring' -Tag 'Out-LongestCommonSubstring' {
    Context 'extracting longest common substring from input string' -Tag 'helper' {
        It 'should return longest common substring' {
            Out-LongestCommonSubstring -InputObject @('Art','Arti') | Should -BeExactly 'Art'
        }

        It 'should return longest common substring (via pipeline)' {
            @('Art','Arti') | Out-LongestCommonSubstring | Should -BeExactly 'Art'
        }

        It 'should return longest common substring (via pipeline)' {
            @('shumë','sot') | Out-LongestCommonSubstring | Should -BeExactly 's'
        }

        It 'should return longest common suffix (via pipeline)' {
            @('Mela','Ela') | Out-LongestCommonSuffix | Should -BeExactly 'ela'
        }

        It 'should return longest common suffix (via pipeline)' {
            @('shumë','mirë') | Out-LongestCommonSuffix | Should -BeExactly 'ë'
        }

        It 'should return longest common substring with different casing (via pipeline)' {
            @('ThisIsJson','THISIsJSON') | Out-LongestCommonSubstring | Should -BeExactly 'ThisIsJson'
        }

        It 'should return longest common case-sensitive substring with different casing (via pipeline)' {
            @('ThisIsJson','THISIsJSON') | Out-LongestCommonSubstring -CaseSensitive | Should -BeExactly 'IsJ'
        }
    }
}