BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Add-RandomWhitespace' -Tag 'Add-RandomWhitespace' {
    Context 'adding whitespace obfuscation to JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
        }

        It 'should return JSON with whitespace added after all tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5
            $jsonObf | Should -BeExactly '{     "Name"     :     "SkyScalpel"     }     '
        }

        It 'should return JSON with tabs added after select tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 2 -Char "`t" -Type BeginObject,NameSeparator,Value
            $jsonObf | Should -BeExactly '{		"Name":		"SkyScalpel"		}'
        }

        It 'should return JSON with whitespace added after tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -Filter 'Name'
            $jsonObf | Should -BeExactly '{"Name"     :"SkyScalpel"}'
        }

        It 'should return JSON with whitespace added after tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -FilterPath '^Name$'
            $jsonObf | Should -BeExactly '{"Name"     :     "SkyScalpel"     }'
        }
    }

    Context 'adding whitespace obfuscation to JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with whitespace added after all tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 2
            $jsonObf | Should -BeExactly '{  "Company"  :  "Permiso Security"  ,  "Tags"  :  [  "Cloud"  ,  "Identity"  ,  "Security"  ,  "CDR (Cloud Detection & Response)"  ]  ,  "IDs"  :  [  116  ,  943  ,  234.567  ,  -38793.1  ]  ,  "Team"  :  {  "Name"  :  "p0 Labs"  ,  "Members"  :  [  {  "FirstName"  :  "Andi"  ,  "LastName"  :  "Ahmeti"  }  ,  {  "FirstName"  :  "Mela"  ,  "LastName"  :  "Elezaj"  }  ,  {  "FirstName"  :  "Enisa"  ,  "LastName"  :  "Hoxhaxhiku"  }  ,  {  "FirstName"  :  "Abian"  ,  "LastName"  :  "Morina"  }  ]  }  ,  "MixedArray"  :  [  "string"  ,  true  ,  false  ,  null  ,  1337  ,  13.37  ,  -13.37  ]  }  '
        }

        It 'should return JSON with tabs added after select tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 1 -Char "`t" -Type BeginArray,ValueSeparator,EndObject
            $jsonObf | Should -BeExactly '{"Company":"Permiso Security",	"Tags":[	"Cloud",	"Identity",	"Security",	"CDR (Cloud Detection & Response)"],	"IDs":[	116,	943,	234.567,	-38793.1],	"Team":{"Name":"p0 Labs",	"Members":[	{"FirstName":"Andi",	"LastName":"Ahmeti"}	,	{"FirstName":"Mela",	"LastName":"Elezaj"}	,	{"FirstName":"Enisa",	"LastName":"Hoxhaxhiku"}	,	{"FirstName":"Abian",	"LastName":"Morina"}	]}	,	"MixedArray":[	"string",	true,	false,	null,	1337,	13.37,	-13.37]}	'
        }

        It 'should return JSON with whitespace added after tokens filtered by token content' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -Filter 'Permiso|Tags|CDR|Labs|true|1337'
            $jsonObf | Should -BeExactly '{"Company":"Permiso Security"     ,"Tags"     :["Cloud","Identity","Security","CDR (Cloud Detection & Response)"     ],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs"     ,"Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true     ,false,null,1337     ,13.37,-13.37]}'
        }

        It 'should return JSON with whitespace added after tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -FilterPath '^Team\.Members'
            $jsonObf | Should -BeExactly '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members"     :     [     {     "FirstName"     :     "Andi"     ,     "LastName"     :     "Ahmeti"     }     ,     {     "FirstName"     :     "Mela"     ,     "LastName"     :     "Elezaj"     }     ,     {     "FirstName"     :     "Enisa"     ,     "LastName"     :     "Hoxhaxhiku"     }     ,     {     "FirstName"     :     "Abian"     ,     "LastName"     :     "Morina"     }     ]     },"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }
    }

    Context 'adding whitespace obfuscation to JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with whitespace added after all tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 2
            $jsonObf | Should -BeExactly '{     "Com\u0070a\u006ey"     :      "Pe\u0072miso\u0020Securi\u0074y"     ,      "T\u0061gs"        :     [     "Clo\u0075d"       ,     "Identity"     ,     "Sec\u0075\u0072ity"        ,      "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"      ]      ,     "IDs"        :        [      116     ,      943     ,      234.567        ,       -38793.1     ]       ,       "Tea\u006d"       :     {        "Name"       :      "p\u0030 Lab\u0073"     ,       "M\u0065m\u0062ers"       :       [        {        "FirstName"      :      "An\u0064i"        ,     "\u004cast\u004e\u0061\u006de"     :     "A\u0068m\u0065ti"      }     ,        {      "\u0046\u0069\u0072stN\u0061\u006d\u0065"        :        "M\u0065la"      ,        "L\u0061stNa\u006de"       :       "Elezaj"     }      ,      {        "Fi\u0072\u0073t\u004eame"     :     "Enisa"      ,     "Last\u004eame"     :       "H\u006fxhaxhi\u006b\u0075"     }        ,     {      "Firs\u0074Nam\u0065"        :        "A\u0062ia\u006e"       ,     "\u004cas\u0074Nam\u0065"        :     "\u004d\u006f\u0072ina"      }     ]      }        ,      "Mix\u0065\u0064Arra\u0079"     :      [        "\u0073\u0074ri\u006e\u0067"        ,       true      ,      false     ,        null        ,     1337     ,        13.37     ,       -13.37       ]       }     '
        }

        It 'should return JSON with tabs added after select tokens' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 1 -Char "`t" -Type BeginArray,Name,EndObject
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey"	 :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"	    : [	 "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"	    :    [	  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"	   : {    "Name"	   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"	   :   [	    {    "FirstName"	  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de"	 : "A\u0068m\u0065ti"  }	 ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"	    :    "M\u0065la"  ,    "L\u0061stNa\u006de"	   :   "Elezaj" }	  ,  {    "Fi\u0072\u0073t\u004eame"	 : "Enisa"  , "Last\u004eame"	 :   "H\u006fxhaxhi\u006b\u0075" }	    , {  "Firs\u0074Nam\u0065"	    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"	    : "\u004d\u006f\u0072ina"  }	 ]  }	    ,  "Mix\u0065\u0064Arra\u0079"	 :  [	    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   }	 '
        }

        It 'should return JSON with whitespace added after tokens filtered by decoded token content' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -FilterDecoded 'Permiso|Tags|Cloud|Security|Labs|MixedArray'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y"      ,  "T\u0061gs"         : [ "Clo\u0075d"        , "Identity" , "Sec\u0075\u0072ity"         ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"       ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073"      ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079"      :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with whitespace added after tokens filtered by decoded JSON path' {
            $jsonObf = $json | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 5 -FilterPathDecoded '^(Tags|Team\.Members.First)'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"              :           [           "Clo\u0075d"             ,           "Identity"           ,           "Sec\u0075\u0072ity"              ,            "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"            ]       , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"            :            "An\u0064i"         , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"              :              "M\u0065la"       ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame"           :           "Enisa"       , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"              :              "A\u0062ia\u006e"        , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }
    }
}