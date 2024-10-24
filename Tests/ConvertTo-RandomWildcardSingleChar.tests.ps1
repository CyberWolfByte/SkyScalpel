BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-RandomWildcardSingleChar' -Tag 'ConvertTo-RandomWildcardSingleChar' {
    Context 'converting input string to single-character wildcard obfuscation syntax' -Tag 'helper' {
        It 'should return plaintext format single-character wildcard obfuscation inserted before eligible characters' {
            $RandomWildcardSingleCharStr = 'Kosovë' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Plaintext
            $RandomWildcardSingleCharStr | Should -BeExactly '??????'
        }

        It 'should return plaintext format single-character wildcard obfuscation for select characters included' {
            $RandomWildcardSingleCharStr = 'Kukës' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Plaintext -Include 'K','k','ë'
            $RandomWildcardSingleCharStr | Should -BeExactly '?u??s'
        }

        It 'should return plaintext format single-character wildcard obfuscation for select characters excluded' {
            $RandomWildcardSingleCharStr = 'Kukës' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Plaintext -Exclude 'K','k','ë'
            $RandomWildcardSingleCharStr | Should -BeExactly 'K?kë?'
        }

        It 'should return unicode format single-character wildcard obfuscation for select characters included and excluded' {
            $RandomWildcardSingleCharStr = 'Kukës' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Unicode -Include 'K','k','ë' -Exclude 'K','k'
            $RandomWildcardSingleCharStr | Should -BeIn @('Kuk\u003Fs','Kuk\u003fs')
        }

        It 'should return matching format single-character wildcard obfuscation (with abnormal input parameter casing) for select characters included' {
            $RandomWildcardSingleCharStr = 'Kukë\u0073' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format MatcHiNg -Include 'K','k','ë'
            $RandomWildcardSingleCharStr | Should -BeExactly '?u??\u0073'
        }

        It 'should skip plaintext format single-character wildcard obfuscation of protected encapsulating double quote characters' {
            $RandomWildcardSingleCharStr = '"Kukës"' | ConvertTo-RandomWildcardSingleChar -RandomCharPercent 100 -Format Plaintext
            $RandomWildcardSingleCharStr | Should -BeExactly '"?????"'
        }
    }
}