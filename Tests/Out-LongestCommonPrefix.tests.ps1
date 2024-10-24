BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Out-LongestCommonPrefix' -Tag 'Out-LongestCommonPrefix' {
    Context 'extracting longest common prefix from input string' -Tag 'helper' {
        It 'should return longest common prefix' {
            Out-LongestCommonPrefix -InputObject @('Art','Arti') | Should -BeExactly 'Art'
        }

        It 'should return longest common prefix (via pipeline)' {
            @('Art','Arti') | Out-LongestCommonPrefix | Should -BeExactly 'Art'
        }

        It 'should return longest common prefix (via pipeline)' {
            @('shumë','sot') | Out-LongestCommonPrefix | Should -BeExactly 's'
        }

        It 'should return longest common prefix with different casing (via pipeline)' {
            @('ThisIsJson','ThisIsJSON') | Out-LongestCommonPrefix | Should -BeExactly 'ThisIsJson'
        }

        It 'should return longest common case-sensitive prefix with different casing (via pipeline)' {
            @('ThisIsJson','ThisIsJSON') | Out-LongestCommonPrefix -CaseSensitive | Should -BeExactly 'ThisIsJ'
        }
    }
}