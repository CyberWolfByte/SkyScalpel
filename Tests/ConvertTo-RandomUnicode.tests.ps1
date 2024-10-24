BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-RandomUnicode' -Tag 'ConvertTo-RandomUnicode' {
    Context 'converting input string to unicode encoding syntax' -Tag 'helper' {
        It 'should return uppercase unicode encoding' {
            $randomUnicodeEncodedStr = 'Kosovë' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Upper
            $randomUnicodeEncodedStr | Should -BeExactly '\u004B\u006F\u0073\u006F\u0076\u00EB'
        }

        It 'should return lowercase unicode encoding' {
            $randomUnicodeEncodedStr = 'Kosovë' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Lower
            $randomUnicodeEncodedStr | Should -BeExactly '\u004b\u006f\u0073\u006f\u0076\u00eb'
        }

        It 'should return uppercase unicode encoding (with abnormal input parameter casing)' {
            $randomUnicodeEncodedStr = 'Kosovë' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case uPPer
            $randomUnicodeEncodedStr | Should -BeExactly '\u004B\u006F\u0073\u006F\u0076\u00EB'
        }

        It 'should return lowercase unicode encoding (with abnormal input parameter casing)' {
            $randomUnicodeEncodedStr = 'Kosovë' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case lOWer
            $randomUnicodeEncodedStr | Should -BeExactly '\u004b\u006f\u0073\u006f\u0076\u00eb'
        }

        It 'should return unicode encoding for select characters included' {
            $randomUnicodeEncodedStr = 'Kukës' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Upper -Include 'K','k','ë'
            $randomUnicodeEncodedStr | Should -BeExactly '\u004Bu\u006B\u00EBs'
        }

        It 'should return unicode encoding for select characters excluded' {
            $randomUnicodeEncodedStr = 'Kukës' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Upper -Exclude 'K','k','ë'
            $randomUnicodeEncodedStr | Should -BeExactly 'K\u0075kë\u0073'
        }

        It 'should return unicode encoding for select characters included and excluded' {
            $randomUnicodeEncodedStr = 'Kukës' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Upper -Include 'K','k','ë' -Exclude 'K','k'
            $randomUnicodeEncodedStr | Should -BeExactly 'Kuk\u00EBs'
        }

        It 'should skip unicode encoding protected encapsulating double quote characters' {
            $randomUnicodeEncodedStr = '"Kukës"' | ConvertTo-RandomUnicode -RandomCharPercent 100 -Case Lower
            $randomUnicodeEncodedStr | Should -BeExactly '"\u004b\u0075\u006b\u00eb\u0073"'
        }
    }
}