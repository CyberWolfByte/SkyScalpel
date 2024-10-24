BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Remove-RandomWhitespace' -Tag 'Remove-RandomWhitespace' {
    Context 'removing whitespace obfuscation from JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
        }

        It 'should return JSON with whitespace removed after all tokens' {
            $jsonObf = '{     "Name"     :     "SkyScalpel"     }     '
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with tabs removed after select tokens' {
            $jsonObf = '{		"Name":		"SkyScalpel"		}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -Include "`t" -Type BeginObject,NameSeparator,Value
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by token content' {
            $jsonObf = '{"Name"     :"SkyScalpel"}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -Filter 'Name'
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by JSON path' {
            $jsonObf = '{"Name"     :     "SkyScalpel"     }'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterPath '^Name$'
            $jsonDeobf | Should -BeExactly $json
        }
    }

    Context 'removing whitespace obfuscation from JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with whitespace removed after all tokens' {
            $jsonObf = '{  "Company"  :  "Permiso Security"  ,  "Tags"  :  [  "Cloud"  ,  "Identity"  ,  "Security"  ,  "CDR (Cloud Detection & Response)"  ]  ,  "IDs"  :  [  116  ,  943  ,  234.567  ,  -38793.1  ]  ,  "Team"  :  {  "Name"  :  "p0 Labs"  ,  "Members"  :  [  {  "FirstName"  :  "Andi"  ,  "LastName"  :  "Ahmeti"  }  ,  {  "FirstName"  :  "Mela"  ,  "LastName"  :  "Elezaj"  }  ,  {  "FirstName"  :  "Enisa"  ,  "LastName"  :  "Hoxhaxhiku"  }  ,  {  "FirstName"  :  "Abian"  ,  "LastName"  :  "Morina"  }  ]  }  ,  "MixedArray"  :  [  "string"  ,  true  ,  false  ,  null  ,  1337  ,  13.37  ,  -13.37  ]  }  '
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with tabs removed after select tokens' {
            $jsonObf = '{"Company":"Permiso Security",	"Tags":[	"Cloud",	"Identity",	"Security",	"CDR (Cloud Detection & Response)"],	"IDs":[	116,	943,	234.567,	-38793.1],	"Team":{"Name":"p0 Labs",	"Members":[	{"FirstName":"Andi",	"LastName":"Ahmeti"}	,	{"FirstName":"Mela",	"LastName":"Elezaj"}	,	{"FirstName":"Enisa",	"LastName":"Hoxhaxhiku"}	,	{"FirstName":"Abian",	"LastName":"Morina"}	]}	,	"MixedArray":[	"string",	true,	false,	null,	1337,	13.37,	-13.37]}	'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -Include "`t" -Type BeginArray,ValueSeparator,EndObject
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by token content' {
            $jsonObf = '{"Company":"Permiso Security"     ,"Tags"     :["Cloud","Identity","Security","CDR (Cloud Detection & Response)"     ],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs"     ,"Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true     ,false,null,1337     ,13.37,-13.37]}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -Filter 'Permiso|Tags|CDR|Labs|true|1337'
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by JSON path' {
            $jsonObf = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members"     :     [     {     "FirstName"     :     "Andi"     ,     "LastName"     :     "Ahmeti"     }     ,     {     "FirstName"     :     "Mela"     ,     "LastName"     :     "Elezaj"     }     ,     {     "FirstName"     :     "Enisa"     ,     "LastName"     :     "Hoxhaxhiku"     }     ,     {     "FirstName"     :     "Abian"     ,     "LastName"     :     "Morina"     }     ]     },"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterPath '^Team\.Members'
            $jsonDeobf | Should -BeExactly $json
        }
    }

    Context 'removing whitespace obfuscation from JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{"Com\u0070a\u006ey":"Pe\u0072miso\u0020Securi\u0074y","T\u0061gs":["Clo\u0075d","Identity","Sec\u0075\u0072ity","CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"],"IDs":[116,943,234.567,-38793.1],"Tea\u006d":{"Name":"p\u0030 Lab\u0073","M\u0065m\u0062ers":[{"FirstName":"An\u0064i","\u004cast\u004e\u0061\u006de":"A\u0068m\u0065ti"},{"\u0046\u0069\u0072stN\u0061\u006d\u0065":"M\u0065la","L\u0061stNa\u006de":"Elezaj"},{"Fi\u0072\u0073t\u004eame":"Enisa","Last\u004eame":"H\u006fxhaxhi\u006b\u0075"},{"Firs\u0074Nam\u0065":"A\u0062ia\u006e","\u004cas\u0074Nam\u0065":"\u004d\u006f\u0072ina"}]},"Mix\u0065\u0064Arra\u0079":["\u0073\u0074ri\u006e\u0067",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with whitespace removed after all tokens' {
            $jsonObf = '{     "Com\u0070a\u006ey"     :      "Pe\u0072miso\u0020Securi\u0074y"     ,      "T\u0061gs"        :     [     "Clo\u0075d"       ,     "Identity"     ,     "Sec\u0075\u0072ity"        ,      "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"      ]      ,     "IDs"        :        [      116     ,      943     ,      234.567        ,       -38793.1     ]       ,       "Tea\u006d"       :     {        "Name"       :      "p\u0030 Lab\u0073"     ,       "M\u0065m\u0062ers"       :       [        {        "FirstName"      :      "An\u0064i"        ,     "\u004cast\u004e\u0061\u006de"     :     "A\u0068m\u0065ti"      }     ,        {      "\u0046\u0069\u0072stN\u0061\u006d\u0065"        :        "M\u0065la"      ,        "L\u0061stNa\u006de"       :       "Elezaj"     }      ,      {        "Fi\u0072\u0073t\u004eame"     :     "Enisa"      ,     "Last\u004eame"     :       "H\u006fxhaxhi\u006b\u0075"     }        ,     {      "Firs\u0074Nam\u0065"        :        "A\u0062ia\u006e"       ,     "\u004cas\u0074Nam\u0065"        :     "\u004d\u006f\u0072ina"      }     ]      }        ,      "Mix\u0065\u0064Arra\u0079"     :      [        "\u0073\u0074ri\u006e\u0067"        ,       true      ,      false     ,        null        ,     1337     ,        13.37     ,       -13.37       ]       }     '
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with tabs removed after select tokens' {
            $jsonObf = '{"Com\u0070a\u006ey"		:"Pe\u0072miso\u0020Securi\u0074y","T\u0061gs"		:[		"Clo\u0075d","Identity","Sec\u0075\u0072ity","CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"],"IDs"		:[		116,943,234.567,-38793.1],"Tea\u006d"		:{"Name"		:"p\u0030 Lab\u0073","M\u0065m\u0062ers"		:[		{"FirstName"		:"An\u0064i","\u004cast\u004e\u0061\u006de"		:"A\u0068m\u0065ti"}		,{"\u0046\u0069\u0072stN\u0061\u006d\u0065"		:"M\u0065la","L\u0061stNa\u006de"		:"Elezaj"}		,{"Fi\u0072\u0073t\u004eame"		:"Enisa","Last\u004eame"		:"H\u006fxhaxhi\u006b\u0075"}		,{"Firs\u0074Nam\u0065"		:"A\u0062ia\u006e","\u004cas\u0074Nam\u0065"		:"\u004d\u006f\u0072ina"}		]}		,"Mix\u0065\u0064Arra\u0079"		:[		"\u0073\u0074ri\u006e\u0067",true,false,null,1337,13.37,-13.37]}		'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -Include "`t" -Type BeginArray,Name,EndObject
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by decoded token content' {
            $jsonObf = '{"Com\u0070a\u006ey":"Pe\u0072miso\u0020Securi\u0074y"     ,"T\u0061gs"     :["Clo\u0075d"     ,"Identity","Sec\u0075\u0072ity"     ,"CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"     ],"IDs":[116,943,234.567,-38793.1],"Tea\u006d":{"Name":"p\u0030 Lab\u0073"     ,"M\u0065m\u0062ers":[{"FirstName":"An\u0064i","\u004cast\u004e\u0061\u006de":"A\u0068m\u0065ti"},{"\u0046\u0069\u0072stN\u0061\u006d\u0065":"M\u0065la","L\u0061stNa\u006de":"Elezaj"},{"Fi\u0072\u0073t\u004eame":"Enisa","Last\u004eame":"H\u006fxhaxhi\u006b\u0075"},{"Firs\u0074Nam\u0065":"A\u0062ia\u006e","\u004cas\u0074Nam\u0065":"\u004d\u006f\u0072ina"}]},"Mix\u0065\u0064Arra\u0079"     :["\u0073\u0074ri\u006e\u0067",true,false,null,1337,13.37,-13.37]}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterDecoded 'Permiso|Tags|Cloud|Security|Labs|MixedArray'
            $jsonDeobf | Should -BeExactly $json
        }

        It 'should return JSON with whitespace removed after tokens filtered by decoded JSON path' {
            $jsonObf = '{"Com\u0070a\u006ey":"Pe\u0072miso\u0020Securi\u0074y","T\u0061gs"     :     [     "Clo\u0075d"     ,     "Identity"     ,     "Sec\u0075\u0072ity"     ,     "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"     ]     ,"IDs":[116,943,234.567,-38793.1],"Tea\u006d":{"Name":"p\u0030 Lab\u0073","M\u0065m\u0062ers":[{"FirstName"     :     "An\u0064i"     ,"\u004cast\u004e\u0061\u006de":"A\u0068m\u0065ti"},{"\u0046\u0069\u0072stN\u0061\u006d\u0065"     :     "M\u0065la"     ,"L\u0061stNa\u006de":"Elezaj"},{"Fi\u0072\u0073t\u004eame"     :     "Enisa"     ,"Last\u004eame":"H\u006fxhaxhi\u006b\u0075"},{"Firs\u0074Nam\u0065"     :     "A\u0062ia\u006e"     ,"\u004cas\u0074Nam\u0065":"\u004d\u006f\u0072ina"}]},"Mix\u0065\u0064Arra\u0079":["\u0073\u0074ri\u006e\u0067",true,false,null,1337,13.37,-13.37]}'
            $jsonDeobf = $jsonObf | Remove-RandomWhitespace -RandomNodePercent 100 -RandomCharPercent 100 -FilterPathDecoded '^(Tags|Team\.Members.First)'
            $jsonDeobf | Should -BeExactly $json
        }
    }
}