BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Remove-RandomWildcardSingleChar' -Tag 'Remove-RandomWildcardSingleChar' {
    Context 'removing single-character wildcard obfuscation from JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $jsonObf = $jsonObf = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:Creat?U???","iam:C?ea?eA??essKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}'
        }
    }

    Context 'removing single-character wildcard obfuscation from JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $jsonObf = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*e???Us*","iam:*?r*A?c*K?y"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*eateUs*","iam:*Cr*Acc*Key"],"Resource":"*"}]}'
        }
    }

    Context 'removing single-character wildcard obfuscation from JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $jsonObf = '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:?rea\u003f?Us\u003Fr","i\u0061m:?\u003fe?\u003F?\u003F??e?\u003f??y"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed in select tokens filtered by token content' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Filter '^(?i)iam:'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:?\u003fe?\u003F?\u003F??e?\u003f??y"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed in select tokens filtered by decoded token content' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -FilterDecoded '^(?i)iam:'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed in select tokens filtered by JSON path' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -FilterPath '^Statement\.NotAction'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:?rea\u003f?Us\u003Fr","i\u0061m:?\u003fe?\u003F?\u003F??e?\u003f??y"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation removed in select tokens filtered by decoded JSON path' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -FilterPathDecoded '^Statement\.NotAction'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }
    }
}