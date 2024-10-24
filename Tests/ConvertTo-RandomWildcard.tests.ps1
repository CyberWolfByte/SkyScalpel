BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-RandomWildcard' -Tag 'ConvertTo-RandomWildcard' {
    Context 'converting input string to wildcard obfuscation syntax' -Tag 'helper' {
        It 'should return plaintext format wildcard obfuscation inserted before eligible characters' {
            $randomWildcardStr = 'Kosovë' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type InsertBefore
            $randomWildcardStr | Should -BeExactly '*K*o*s*o*v*ë'
        }

        It 'should return plaintext format wildcard obfuscation inserted after eligible characters' {
            $randomWildcardStr = 'Kosovë' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type InsertAfter
            $randomWildcardStr | Should -BeExactly 'K*o*s*o*v*ë*'
        }

        It 'should return plaintext format wildcard obfuscation replacing eligible characters' {
            $randomWildcardStr = 'Kosovë' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace
            $randomWildcardStr | Should -BeExactly '******'
        }

        It 'should return plaintext format wildcard obfuscation for select characters included' {
            $randomWildcardStr = 'Kukës' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'K','k','ë'
            $randomWildcardStr | Should -BeExactly '*u**s'
        }

        It 'should return plaintext format wildcard obfuscation for select characters excluded' {
            $randomWildcardStr = 'Kukës' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Exclude 'K','k','ë'
            $randomWildcardStr | Should -BeExactly 'K*kë*'
        }

        It 'should return unicode format wildcard obfuscation for select characters included and excluded' {
            $randomWildcardStr = 'Kukës' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Unicode -Type InsertAfter -Include 'K','k','ë' -Exclude 'K','k'
            $randomWildcardStr | Should -BeIn @('Kukë\u002as','Kukë\u002As')
        }

        It 'should return matching format wildcard obfuscation (with abnormal input parameter casing) for select characters included' {
            $randomWildcardStr = 'Kukë\u0073' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 2 -Format MatcHiNg -Type RePlAce -Include 'K','k','ë'
            $randomWildcardStr | Should -BeExactly '**u****\u0073'
        }

        It 'should skip plaintext format wildcard obfuscation of protected encapsulating double quote characters' {
            $randomWildcardStr = '"Kukës"' | ConvertTo-RandomWildcard -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace
            $randomWildcardStr | Should -BeExactly '"*****"'
        }
    }
}