BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-RandomCase' -Tag 'ConvertTo-RandomCase' {
    Context 'converting input string to randomized character casing' -Tag 'helper' {
        It 'should return inverted casing for all characters' {
            $randomCaseStr = 'Kosovë' | ConvertTo-RandomCase -RandomCharPercent 100
            $randomCaseStr | Should -BeExactly 'kOSOVË'
        }

        It 'should return inverted casing for select characters included' {
            $randomCaseStr = 'Kukës' | ConvertTo-RandomCase -RandomCharPercent 100 -Include 'K','k','ë'
            $randomCaseStr | Should -BeExactly 'kuKËs'
        }

        It 'should return inverted casing for select characters excluded' {
            $randomCaseStr = 'Kukës' | ConvertTo-RandomCase -RandomCharPercent 100 -Exclude 'K','k','ë'
            $randomCaseStr | Should -BeExactly 'KUkëS'
        }

        It 'should return inverted casing for select characters included and excluded' {
            $randomCaseStr = 'Kukës' | ConvertTo-RandomCase -RandomCharPercent 100 -Include 'K','k','ë' -Exclude 'K','k'
            $randomCaseStr | Should -BeExactly 'KukËs'
        }

        It 'should skip inverted casing protected encapsulating double quote characters' {
            $randomCaseStr = '"Kukës"' | ConvertTo-RandomCase -RandomCharPercent 100
            $randomCaseStr | Should -BeExactly '"kUKËS"'
        }
    }
}