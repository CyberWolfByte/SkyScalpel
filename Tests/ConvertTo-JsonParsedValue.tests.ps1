BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-JsonParsedValue' -Tag 'ConvertTo-JsonParsedValue' {
    Context 'converting input string to array of parsed JSON character objects' -Tag 'helper' {
        BeforeAll {
            $jsonStrDecoded = 'Gjakova, Kosovë == 07'
            $jsonStr = 'Gjakova, Ko\u0073ov\u00EB == 07'
            $parsedCharArr = $jsonStr | ConvertTo-JsonParsedValue
        }

        It 'should return parsed character object count' {
            $parsedCharArr.Count | Should -BeExactly 21
        }

        It 'should return IsDecoded for all character objects' {
            $parsedCharArr.ForEach( { $_.IsDecoded } ) | Should -BeExactly @($false,$false,$false,$false,$false,$false,$false,$false,$false,$false,$false,$true,$false,$false,$true,$false,$false,$false,$false,$false,$false)
        }

        It 'should return Format for all character objects' {
            $parsedCharArr.ForEach( { $_.Format } ) | Should -BeExactly @('Default','Default','Default','Default','Default','Default','Default','Default','Default','Default','Default','Hex','Default','Default','Hex','Default','Default','Default','Default','Default','Default')
        }

        It 'should return Class for all character objects' {
            $parsedCharArr.ForEach( { $_.Class } ) | Should -BeExactly @('Alpha','Alpha','Alpha','Alpha','Alpha','Alpha','Alpha','Special','Special','Alpha','Alpha','Alpha','Alpha','Alpha','Undefined','Special','Special','Special','Special','Num','Num')
        }

        It 'should return Case for all character objects' {
            $parsedCharArr.ForEach( { $_.Case } ) | Should -BeExactly @('Upper','Lower','Lower','Lower','Lower','Lower','Lower','NA','NA','Upper','Lower','Lower','Lower','Lower','Undefined','NA','NA','NA','NA','NA','NA')
        }

        It 'should return IsPrintable for all character objects' {
            $parsedCharArr.ForEach( { $_.IsPrintable } ) | Should -BeExactly @($true,$true,$true,$true,$true,$true,$true,$true,$true,$true,$true,$true,$true,$true,$false,$true,$true,$true,$true,$true,$true)
        }

        It 'should return Content for all character objects' {
            $parsedCharArr.ForEach( { $_.Content } ) | Should -BeExactly @('G','j','a','k','o','v','a',',',' ','K','o','\u0073','o','v','\u00EB',' ','=','=',' ','0','7')
        }

        It 'should return re-concatenated Content for all character objects' {
            -join$parsedCharArr.ForEach( { $_.Content } ) | Should -BeExactly $jsonStr
        }

        It 'should return ContentDecoded for all character objects' {
            $parsedCharArr.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('G','j','a','k','o','v','a',',',' ','K','o','s','o','v','ë',' ','=','=',' ','0','7')
        }

        It 'should return re-concatenated ContentDecoded for all character objects' {
            -join$parsedCharArr.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $jsonStrDecoded
        }

        It 'should return re-concatenated ContentDecoded for all character objects' {
            ('"quotedStr"' | ConvertTo-JsonParsedValue).ForEach( { $_.Format } ) | Should -BeExactly @('Protected','Default','Default','Default','Default','Default','Default','Default','Default','Default','Protected')
        }
    }
}