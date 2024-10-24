BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Add-RandomCase' -Tag 'Add-RandomCase' {
    Context 'adding case inversion obfuscation to JSON (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
        }

        It 'should return JSON with case inversion applied to all tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100
            $jsonObf | Should -BeExactly '{"nAME":"sKYsCALPEL"}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -Include 'a','e'
            $jsonObf | Should -BeExactly '{"Name":"SkyScAlpEl"}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e' -Filter 'Name'
            $jsonObf | Should -BeExactly '{"naMe":"SkyScalpel"}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e' -FilterPath '^Name$'
            $jsonObf | Should -BeExactly '{"naMe":"sKYsCaLPeL"}'
        }
    }

    Context 'adding case inversion obfuscation to JSON (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with case inversion applied to all tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100
            $jsonObf | Should -BeExactly '{"cOMPANY":"pERMISO sECURITY","tAGS":["cLOUD","iDENTITY","sECURITY","cdr (cLOUD dETECTION & rESPONSE)"],"idS":[116,943,234.567,-38793.1],"tEAM":{"nAME":"P0 lABS","mEMBERS":[{"fIRSTnAME":"aNDI","lASTnAME":"aHMETI"},{"fIRSTnAME":"mELA","lASTnAME":"eLEZAJ"},{"fIRSTnAME":"eNISA","lASTnAME":"hOXHAXHIKU"},{"fIRSTnAME":"aBIAN","lASTnAME":"mORINA"}]},"mIXEDaRRAY":["STRING",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -Include 'a','e','i','o','u'
            $jsonObf | Should -BeExactly '{"Company":"PErmIsO SEcUrIty","Tags":["ClOUd","IdEntIty","SEcUrIty","CDR (ClOUd DEtEctIOn & REspOnsE)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 LAbs","Members":[{"FirstName":"AndI","LastName":"AhmEtI"},{"FirstName":"MElA","LastName":"ElEzAj"},{"FirstName":"EnIsA","LastName":"HOxhAxhIkU"},{"FirstName":"AbIAn","LastName":"MOrInA"}]},"MixedArray":["strIng",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by token content' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e','i','o','u' -Filter 'Permiso|CDR|Cloud|Security'
            $jsonObf | Should -BeExactly '{"Company":"peRMiSo seCuRiTY","Tags":["cLouD","Identity","seCuRiTY","cdr (cLouD deTeCTioN & reSPoNSe)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by JSON path' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e','i','o','u' -FilterPath '^Team\.Members'
            $jsonObf | Should -BeExactly '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","meMBeRS":[{"fiRSTnaMe":"aNDi","laSTnaMe":"aHMeTi"},{"fiRSTnaMe":"meLa","laSTnaMe":"eLeZaJ"},{"fiRSTnaMe":"eNiSa","laSTnaMe":"hoXHaXHiKu"},{"fiRSTnaMe":"aBiaN","laSTnaMe":"moRiNa"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        }
    }

    Context 'adding case inversion obfuscation to JSON (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with case inversion applied to all tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100
            $jsonObf | Should -BeExactly '{ "cOM\u0050A\u004eY" :  "pE\u0052MISO\u0020sECURI\u0054Y" ,  "t\u0041GS"    : [ "cLO\u0055D"   , "iDENTITY" , "sEC\u0055\u0052ITY"    ,  "cdr (cLOUD\u0020d\u0045TECTI\u004fN \u0026 rESPO\u004eS\u0045)"  ]  , "idS"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "tEA\u004d"   : {    "nAME"   :  "P\u0030 lAB\u0053" ,   "m\u0045M\u0042ERS"   :   [    {    "fIRSTnAME"  :  "aN\u0044I"    , "\u006cAST\u006e\u0041\u004dE" : "a\u0048M\u0045TI"  } ,    {  "\u0066\u0049\u0052STn\u0041\u004d\u0045"    :    "m\u0045LA"  ,    "l\u0041STnA\u004dE"   :   "eLEZAJ" }  ,  {    "fI\u0052\u0053T\u006eAME" : "eNISA"  , "lAST\u006eAME" :   "h\u004fXHAXHI\u004b\u0055" }    , {  "fIRS\u0054nAM\u0045"    :    "a\u0042IA\u004e"   , "\u006cAS\u0054nAM\u0045"    : "\u006d\u004f\u0052INA"  } ]  }    ,  "mIX\u0045\u0044aRRA\u0059" :  [    "\u0053\u0054RI\u004e\u0047"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with case inversion applied to select characters in select tokens' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Type Value -Include 'a','e','i','o','u'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "PE\u0072mIsO\u0020SEcUrI\u0074y" ,  "T\u0061gs"    : [ "ClO\u0055d"   , "IdEntIty" , "SEc\u0055\u0072Ity"    ,  "CDR (ClOUd\u0020D\u0045tEctI\u004fn \u0026 REspO\u006es\u0045)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 LAb\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064I"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0045tI"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0045lA"  ,    "L\u0061stNa\u006de"   :   "ElEzAj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "EnIsA"  , "Last\u004eame" :   "H\u004fxhAxhI\u006b\u0055" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062IA\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u004f\u0072InA"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074rI\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by decoded token content' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e','i','o','u' -FilterDecoded 'Permiso|CDR|Cloud|Security'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "pe\u0052MiSo\u0020seCuRi\u0054Y" ,  "T\u0061gs"    : [ "cLo\u0075D"   , "Identity" , "seC\u0075\u0052iTY"    ,  "cdr (cLouD\u0020d\u0065TeCTi\u006fN \u0026 reSPo\u004eS\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }

        It 'should return JSON with case inversion applied to select characters in select tokens filtered by decoded JSON path' {
            $jsonObf = $json | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100 -Exclude 'a','e','i','o','u' -FilterPathDecoded '^Team\.Members'
            $jsonObf | Should -BeExactly '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "m\u0065M\u0042eRS"   :   [    {    "fiRSTnaMe"  :  "aN\u0044i"    , "\u006caST\u006e\u0061\u004de" : "a\u0048M\u0065Ti"  } ,    {  "\u0066\u0069\u0052STn\u0061\u004d\u0065"    :    "m\u0065La"  ,    "l\u0061STna\u004de"   :   "eLeZaJ" }  ,  {    "fi\u0052\u0053T\u006eaMe" : "eNiSa"  , "laST\u006eaMe" :   "h\u006fXHaXHi\u004b\u0075" }    , {  "fiRS\u0054naM\u0065"    :    "a\u0042ia\u004e"   , "\u006caS\u0054naM\u0065"    : "\u006d\u006f\u0052iNa"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
        }
    }
}