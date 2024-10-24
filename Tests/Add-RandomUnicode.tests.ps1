BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Add-RandomUnicode' -Tag 'Add-RandomUnicode' {
    Context 'adding unicode encoding obfuscation to JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
        }

        It 'should return JSON with lowercase unicode encoding applied to all tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower
            $jsonObf | Should -BeExactly '{"\u004e\u0061\u006d\u0065":"\u0053\u006b\u0079\u0053\u0063\u0061\u006c\u0070\u0065\u006c"}'
        }

        It 'should return JSON with lowercase unicode encoding applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower -Type Value -Include 'a','e'
            $jsonObf | Should -BeExactly '{"Name":"SkySc\u0061lp\u0065l"}'
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e' -Filter 'Name'
            $jsonObf | Should -BeExactly '{"\u004Ea\u006De":"SkyScalpel"}'
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e' -FilterPath '^Name$'
            $jsonObf | Should -BeExactly '{"\u004Ea\u006De":"\u0053\u006B\u0079\u0053\u0063a\u006C\u0070e\u006C"}'
        }
    }

    Context 'adding unicode encoding obfuscation to JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with lowercase unicode encoding applied to all tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower
            $jsonObf | Should -BeExactly '{"\u0043\u006f\u006d\u0070\u0061\u006e\u0079":"\u0050\u0065\u0072\u006d\u0069\u0073\u006f\u0020\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079","\u0054\u0061\u0067\u0073":["\u0043\u006c\u006f\u0075\u0064","\u0049\u0064\u0065\u006e\u0074\u0069\u0074\u0079","\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079","\u0043\u0044\u0052\u0020\u0028\u0043\u006c\u006f\u0075\u0064\u0020\u0044\u0065\u0074\u0065\u0063\u0074\u0069\u006f\u006e\u0020\u0026\u0020\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0029"],"\u0049\u0044\u0073":[116,943,234.567,-38793.1],"\u0054\u0065\u0061\u006d":{"\u004e\u0061\u006d\u0065":"\u0070\u0030\u0020\u004c\u0061\u0062\u0073","\u004d\u0065\u006d\u0062\u0065\u0072\u0073":[{"\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065":"\u0041\u006e\u0064\u0069","\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065":"\u0041\u0068\u006d\u0065\u0074\u0069"},{"\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065":"\u004d\u0065\u006c\u0061","\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065":"\u0045\u006c\u0065\u007a\u0061\u006a"},{"\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065":"\u0045\u006e\u0069\u0073\u0061","\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065":"\u0048\u006f\u0078\u0068\u0061\u0078\u0068\u0069\u006b\u0075"},{"\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065":"\u0041\u0062\u0069\u0061\u006e","\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065":"\u004d\u006f\u0072\u0069\u006e\u0061"}]},"\u004d\u0069\u0078\u0065\u0064\u0041\u0072\u0072\u0061\u0079":["\u0073\u0074\u0072\u0069\u006e\u0067",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with lowercase unicode encoding applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower -Type Value -Include 'a','e','i','o','u'
            $jsonObf | Should -BeExactly '{"Company":"P\u0065rm\u0069s\u006f S\u0065c\u0075r\u0069ty","Tags":["Cl\u006f\u0075d","Id\u0065nt\u0069ty","S\u0065c\u0075r\u0069ty","CDR (Cl\u006f\u0075d D\u0065t\u0065ct\u0069\u006fn & R\u0065sp\u006fns\u0065)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 L\u0061bs","Members":[{"FirstName":"And\u0069","LastName":"Ahm\u0065t\u0069"},{"FirstName":"M\u0065l\u0061","LastName":"El\u0065z\u0061j"},{"FirstName":"En\u0069s\u0061","LastName":"H\u006fxh\u0061xh\u0069k\u0075"},{"FirstName":"Ab\u0069\u0061n","LastName":"M\u006fr\u0069n\u0061"}]},"MixedArray":["str\u0069ng",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e','i','o','u' -Filter 'Permiso|CDR|Cloud|Security'
            $jsonObf | Should -BeExactly '{"Company":"\u0050e\u0072\u006Di\u0073o\u0020\u0053e\u0063u\u0072i\u0074\u0079","Tags":["\u0043\u006Cou\u0064","Identity","\u0053e\u0063u\u0072i\u0074\u0079","\u0043\u0044\u0052\u0020\u0028\u0043\u006Cou\u0064\u0020\u0044e\u0074e\u0063\u0074io\u006E\u0020\u0026\u0020\u0052e\u0073\u0070o\u006E\u0073e\u0029"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e','i','o','u' -FilterPath '^Team\.Members'
            $jsonObf | Should -BeExactly '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","\u004De\u006D\u0062e\u0072\u0073":[{"\u0046i\u0072\u0073\u0074\u004Ea\u006De":"\u0041\u006E\u0064i","\u004Ca\u0073\u0074\u004Ea\u006De":"\u0041\u0068\u006De\u0074i"},{"\u0046i\u0072\u0073\u0074\u004Ea\u006De":"\u004De\u006Ca","\u004Ca\u0073\u0074\u004Ea\u006De":"\u0045\u006Ce\u007Aa\u006A"},{"\u0046i\u0072\u0073\u0074\u004Ea\u006De":"\u0045\u006Ei\u0073a","\u004Ca\u0073\u0074\u004Ea\u006De":"\u0048o\u0078\u0068a\u0078\u0068i\u006Bu"},{"\u0046i\u0072\u0073\u0074\u004Ea\u006De":"\u0041\u0062ia\u006E","\u004Ca\u0073\u0074\u004Ea\u006De":"\u004Do\u0072i\u006Ea"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }
    }

    Context 'adding unicode encoding obfuscation to JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with lowercase unicode encoding applied to all tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower
            $jsonObf | Should -BeExactly '{ "\u0043\u006f\u006d\u0070\u0061\u006e\u0079" :  "\u0050\u0065\u0072\u006d\u0069\u0073\u006f\u0020\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079" ,  "\u0054\u0061\u0067\u0073"    : [ "\u0043\u006c\u006f\u0075\u0064"   , "\u0049\u0064\u0065\u006e\u0074\u0069\u0074\u0079" , "\u0053\u0065\u0063\u0075\u0072\u0069\u0074\u0079"    ,  "\u0043\u0044\u0052\u0020\u0028\u0043\u006c\u006f\u0075\u0064\u0020\u0044\u0065\u0074\u0065\u0063\u0074\u0069\u006f\u006e\u0020\u0026\u0020\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0029"  ]  , "\u0049\u0044\u0073"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "\u0054\u0065\u0061\u006d"   : {    "\u004e\u0061\u006d\u0065"   :  "\u0070\u0030\u0020\u004c\u0061\u0062\u0073" ,   "\u004d\u0065\u006d\u0062\u0065\u0072\u0073"   :   [    {    "\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065"  :  "\u0041\u006e\u0064\u0069"    , "\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065" : "\u0041\u0068\u006d\u0065\u0074\u0069"  } ,    {  "\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065"    :    "\u004d\u0065\u006c\u0061"  ,    "\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065"   :   "\u0045\u006c\u0065\u007a\u0061\u006a" }  ,  {    "\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065" : "\u0045\u006e\u0069\u0073\u0061"  , "\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065" :   "\u0048\u006f\u0078\u0068\u0061\u0078\u0068\u0069\u006b\u0075" }    , {  "\u0046\u0069\u0072\u0073\u0074\u004e\u0061\u006d\u0065"    :    "\u0041\u0062\u0069\u0061\u006e"   , "\u004c\u0061\u0073\u0074\u004e\u0061\u006d\u0065"    : "\u004d\u006f\u0072\u0069\u006e\u0061"  } ]  }    ,  "\u004d\u0069\u0078\u0065\u0064\u0041\u0072\u0072\u0061\u0079" :  [    "\u0073\u0074\u0072\u0069\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with lowercase unicode encoding applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Lower -Type Value -Include 'a','e','i','o','u'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "P\u0065\u0072m\u0069s\u006f\u0020S\u0065c\u0075r\u0069\u0074y" ,  "T\u0061gs"    : [ "Cl\u006f\u0075d"   , "Id\u0065nt\u0069ty" , "S\u0065c\u0075\u0072\u0069ty"    ,  "CDR (Cl\u006f\u0075d\u0020D\u0065t\u0065ct\u0069\u006fn \u0026 R\u0065sp\u006f\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 L\u0061b\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064\u0069"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065t\u0069"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065l\u0061"  ,    "L\u0061stNa\u006de"   :   "El\u0065z\u0061j" }  ,  {    "Fi\u0072\u0073t\u004eame" : "En\u0069s\u0061"  , "Last\u004eame" :   "H\u006fxh\u0061xh\u0069\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062\u0069\u0061\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072\u0069n\u0061"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074r\u0069\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by decoded token content' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e','i','o','u' -FilterDecoded 'Permiso|CDR|Cloud|Security'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "\u0050e\u0072\u006Di\u0073o\u0020\u0053e\u0063u\u0072i\u0074\u0079" ,  "T\u0061gs"    : [ "\u0043\u006Co\u0075\u0064"   , "Identity" , "\u0053e\u0063\u0075\u0072i\u0074\u0079"    ,  "\u0043\u0044\u0052\u0020\u0028\u0043\u006Cou\u0064\u0020\u0044\u0065\u0074e\u0063\u0074i\u006f\u006E\u0020\u0026\u0020\u0052e\u0073\u0070o\u006e\u0073\u0065\u0029"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with uppercase unicode encoding applied to select characters in select tokens filtered by decoded JSON path' {
            $jsonObf = $json | Add-RandomUnicode -RandomNodePercent 100 -RandomCharPercent 100 -Case Upper -Exclude 'a','e','i','o','u' -FilterPathDecoded '^Team\.Members'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "\u004D\u0065\u006D\u0062e\u0072\u0073"   :   [    {    "\u0046i\u0072\u0073\u0074\u004Ea\u006De"  :  "\u0041\u006E\u0064i"    , "\u004ca\u0073\u0074\u004e\u0061\u006de" : "\u0041\u0068\u006D\u0065\u0074i"  } ,    {  "\u0046\u0069\u0072\u0073\u0074\u004E\u0061\u006d\u0065"    :    "\u004D\u0065\u006Ca"  ,    "\u004C\u0061\u0073\u0074\u004Ea\u006de"   :   "\u0045\u006Ce\u007Aa\u006A" }  ,  {    "\u0046i\u0072\u0073\u0074\u004ea\u006De" : "\u0045\u006Ei\u0073a"  , "\u004Ca\u0073\u0074\u004ea\u006De" :   "\u0048\u006f\u0078\u0068a\u0078\u0068i\u006b\u0075" }    , {  "\u0046i\u0072\u0073\u0074\u004Ea\u006D\u0065"    :    "\u0041\u0062ia\u006e"   , "\u004ca\u0073\u0074\u004Ea\u006D\u0065"    : "\u004d\u006f\u0072i\u006Ea"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }
    }
}