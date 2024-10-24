BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Add-RandomWildcard' -Tag 'Add-RandomWildcard' {
    Context 'adding wildcard obfuscation to JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Statement":[{"Action":["iam:CreateUser","iam:CreateAccessKey"]}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to all characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type InsertBefore
            $jsonObf | Should -BeExactly '{"Statement":[{"Action":["iam:*C*r*e*a*t*e*U*s*e*r","iam:*C*r*e*a*t*e*A*c*c*e*s*s*K*e*y"]}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a'
            $jsonObf | Should -BeExactly '{"Statement":[{"Action":["iam:Cr**t*Us*r","iam:Cr**t*Acc*ssK*y"]}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a' -Filter 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"Statement":[{"Action":["iam:CreateUser","iam:Cr**t*Acc*ssK*y"]}]}'
        }
    }

    Context 'adding wildcard obfuscation to JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to all characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type InsertBefore
            $jsonObf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*C*r*e*a*t*e*U*s*e*r","iam:*C*r*e*a*t*e*A*c*c*e*s*s*K*e*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a'
            $jsonObf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:Cr**t*Us*r","iam:Cr**t*Acc*ssK*y"],"Resource":"*"}]}'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a' -Filter 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:Cr**t*Acc*ssK*y"],"Resource":"*"}]}'
        }
    }

    Context 'adding wildcard obfuscation to JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T\u0065USEr"  ,  "IA\u004d:\u0063rEa\u0074Ea\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }

        It 'should return JSON with wildcard obfuscation applied to all characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type InsertBefore
            $jsonObf | Should -BeExactly '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:*C*R*E*\u0041*T*\u0065*U*S*E*r"  ,  "IA\u004d:*\u0063*r*E*a*\u0074*E*a*\u0063*c*E*S*s*K*E*y" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a'
            $jsonObf | Should -BeExactly '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T*USEr"  ,  "IA\u004d:\u0063rE*\u0074E*\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }

        It 'should return JSON with wildcard obfuscation applied to select characters in select tokens filtered by decoded token content' {
            $jsonObf = $json | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -RandomLength 1 -Format Plaintext -Type Replace -Include 'e','a' -FilterDecoded 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T\u0065USEr"  ,  "IA\u004d:\u0063rE*\u0074E*\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }
    }
}