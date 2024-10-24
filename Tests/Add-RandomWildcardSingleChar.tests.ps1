BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Add-RandomWildcardSingleChar' -Tag 'Add-RandomWildcardSingleChar' {
    Context 'adding single-character wildcard obfuscation to JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Statement":[{"Action":["iam:CreateUser","iam:CreateAccessKey"]}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a'
            $jsonObf | Should -BeExactly '{"Statement":[{"Action":["iam:Cr??t?Us?r","iam:Cr??t?Acc?ssK?y"]}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a' -Filter 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"Statement":[{"Action":["iam:CreateUser","iam:Cr??t?Acc?ssK?y"]}]}'
        }
    }

    Context 'adding single-character wildcard obfuscation to JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:CreateAccessKey"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a'
            $jsonObf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:Cr??t?Us?r","iam:Cr??t?Acc?ssK?y"],"Resource":"*"}]}'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a' -Filter 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:CreateUser","iam:Cr??t?Acc?ssK?y"],"Resource":"*"}]}'
        }
    }

    Context 'adding single-character wildcard obfuscation to JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T\u0065USEr"  ,  "IA\u004d:\u0063rEa\u0074Ea\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a'
            $jsonObf | Should -BeExactly '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T?USEr"  ,  "IA\u004d:\u0063rE?\u0074E?\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }

        It 'should return JSON with single-character wildcard obfuscation applied to select characters in select tokens filtered by decoded token content' {
            $jsonObf = $json | Add-RandomWildcardSingleChar -RandomNodePercent 100 -RandomCharPercent 100 -Format Plaintext -Include 'e','a' -FilterDecoded 'CreateAccessKey'
            $jsonObf | Should -BeExactly '{"V\u0065rs\u0069on" :"2012-10-17"  ,"Stat\u0065m\u0065nt":   [{"E\u0066fect":"Allo\u0077" ,"Not\u0041\u0063tion"  :["IAm:CRE\u0041T\u0065USEr"  ,  "IA\u004d:\u0063rE?\u0074E?\u0063cESsKEy" ]   ,"R\u0065sou\u0072ce"   :   "*"  }]   }'
        }
    }
}