BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertFrom-RandomUnicode' -Tag 'ConvertFrom-RandomUnicode' {
    Context 'converting input string from unicode encoding syntax' -Tag 'helper' {
        It 'should return string with all unicode encoding syntax removed' {
            $randomUnicodeDecodedStr = '\u004b\u006f\u0073\u006f\u0076\u00eb' | ConvertFrom-RandomUnicode -RandomCharPercent 100
            $randomUnicodeDecodedStr | Should -BeExactly 'Kosovë'
        }

        It 'should return string with unicode encoding syntax removed for select characters included' {
            $randomUnicodeDecodedStr = '\u004B\u0075\u006B\u00EB\u0073' | ConvertFrom-RandomUnicode -RandomCharPercent 100 -Include 'K','k','ë'
            $randomUnicodeDecodedStr | Should -BeExactly 'K\u0075kë\u0073'
        }

        It 'should return string with unicode encoding syntax removed for select characters excluded' {
            $randomUnicodeDecodedStr = '\u004B\u0075\u006B\u00EB\u0073' | ConvertFrom-RandomUnicode -RandomCharPercent 100 -Exclude 'K','k','ë'
            $randomUnicodeDecodedStr | Should -BeExactly '\u004Bu\u006B\u00EBs'
        }

        It 'should return string with unicode encoding syntax removed for select characters included and excluded' {
            $randomUnicodeDecodedStr = '\u004b\u0075\u006b\u00eb\u0073' | ConvertFrom-RandomUnicode -RandomCharPercent 100 -Include 'K','k','ë' -Exclude 'K','k'
            $randomUnicodeDecodedStr | Should -BeExactly '\u004b\u0075\u006bë\u0073'
        }

        It 'should skip unicode decoding protected encapsulating double quote characters' {
            $randomUnicodeDecodedStr = '"\u004b\u0075\u006b\u00eb\u0073"' | ConvertFrom-RandomUnicode -RandomCharPercent 100
            $randomUnicodeDecodedStr | Should -BeExactly '"Kukës"'
        }
    }
}