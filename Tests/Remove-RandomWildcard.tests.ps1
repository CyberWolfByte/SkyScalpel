BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Remove-RandomWildcard' -Tag 'Remove-RandomWildcard' {
    Context 'removing wildcard obfuscation from JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $jsonObf = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:***re***a*eUser","iam:**Cr**eat*A***c**es**sKe**y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for adjacent wildcard tokens' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -Type Adjacent
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*re*a*eUser","iam:*Cr*eat*A*c*es*sKe*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}'
        }
    }

    Context 'removing wildcard obfuscation from JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $jsonObf = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*e*Us*","iam:*r*A*c*K*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for prefixes of up to length 2' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 2 -Type Prefix
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:Cre*eUser","iam:Crea*Acces*Key"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for suffixes of up to length 2' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 2 -Type Suffix
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:C*ateUser","iam:Cr*teAcc*ssKey"],"Resource":"*"}]}'
        }
    }

    Context 'removing wildcard obfuscation from JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $jsonObf = '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:C*e\u002AUs*","i\u0061m:*r\u002AA*c*K*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for prefixes of up to length 2' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 2 -Type Prefix
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:Cre*eUser","i\u0061m:Crea\u002AAcces*Key"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for suffixes of up to length 2' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 2 -Type Suffix
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:C*ateUser","i\u0061m:Cr\u002AteAcc*ssKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters in select tokens filtered by token content' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -Filter '^(?i)iam:'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:*r\u002AA*c*K*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters in select tokens filtered by decoded token content' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -FilterDecoded '^(?i)iam:'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters in select tokens filtered by JSON path' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -FilterPath '^Statement\.NotAction'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:C*e\u002AUs*","i\u0061m:*r\u002AA*c*K*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation removed for all wildcard characters in select tokens filtered by decoded JSON path' {
            $jsonDeobf = $jsonObf | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 10 -FilterPathDecoded '^Statement\.NotAction'
            $jsonDeobf | Should -BeExactly '{"Version":"2012-10-17","Stat\u0065ment":[{"Effect":"Allow","Not\u0041ction":["iam:CreateUser","i\u0061m:CreateAccessKey"],"Resource":"*"}]}'
        }
    }
}