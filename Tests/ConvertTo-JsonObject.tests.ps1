BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'ConvertTo-JsonObject -Target JsonToken' -Tag 'ConvertTo-JsonObject','String' {
    Context 'parsing String from policy (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
            $jsonStr = $json | ConvertTo-JsonObject -Target String
        }

        It 'should return string count' {
            $jsonStr.Count | Should -BeExactly 1
        }

        It 'should return string value' {
            $jsonStr | Should -BeExactly $json
        }
    }
}

Describe 'ConvertTo-JsonObject -Target JsonToken' -Tag 'ConvertTo-JsonObject','JsonToken' {
    Context 'parsing JsonToken tokens from policy (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonToken
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 5
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,7,8,20)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,6,1,12,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject')
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Name"',':','"SkyScalpel"','}')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonToken tokens from policy (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonToken
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 99
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,10,11,29,30,36,37,38,45,46,56,57,67,68,102,103,104,109,110,111,114,115,118,119,126,127,135,136,137,143,144,145,151,152,161,162,171,172,173,174,185,186,192,193,203,204,212,213,214,215,226,227,233,234,244,245,253,254,255,256,267,268,275,276,286,287,299,300,301,302,313,314,321,322,332,333,341,342,343,344,345,357,358,359,367,368,372,373,378,379,383,384,388,389,394,395,401,402)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,9,1,18,1,6,1,1,7,1,10,1,10,1,34,1,1,5,1,1,3,1,3,1,7,1,8,1,1,6,1,1,6,1,9,1,9,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,7,1,10,1,12,1,1,1,11,1,7,1,10,1,8,1,1,1,1,12,1,1,8,1,4,1,5,1,4,1,4,1,5,1,6,1,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,2,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','EndArray','EndObject','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Null','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','EndObject')
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Company"',':','"Permiso Security"',',','"Tags"',':','[','"Cloud"',',','"Identity"',',','"Security"',',','"CDR (Cloud Detection & Response)"',']',',','"IDs"',':','[','116',',','943',',','234.567',',','-38793.1',']',',','"Team"',':','{','"Name"',':','"p0 Labs"',',','"Members"',':','[','{','"FirstName"',':','"Andi"',',','"LastName"',':','"Ahmeti"','}',',','{','"FirstName"',':','"Mela"',',','"LastName"',':','"Elezaj"','}',',','{','"FirstName"',':','"Enisa"',',','"LastName"',':','"Hoxhaxhiku"','}',',','{','"FirstName"',':','"Abian"',',','"LastName"',':','"Morina"','}',']','}',',','"MixedArray"',':','[','"string"',',','true',',','false',',','null',',','1337',',','13.37',',','-13.37',']','}')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonToken tokens from policy (advanced)' -Tag 'advanced' {
        BeforeAll {
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
            $tokens = $json | ConvertTo-JsonObject -Target JsonToken
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 198
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,2,21,22,23,25,58,59,60,62,73,77,78,79,80,81,93,96,97,98,108,109,110,111,131,135,136,138,202,204,205,207,208,209,214,218,219,223,224,226,229,230,231,233,236,237,238,240,247,251,252,255,263,264,265,268,269,272,283,286,287,288,289,293,299,302,303,305,324,325,326,329,348,351,352,355,356,360,361,365,376,378,379,381,392,396,397,398,428,429,430,431,449,451,452,453,454,458,459,461,502,506,507,511,522,524,525,529,549,552,553,556,564,565,566,568,569,571,572,576,602,603,604,605,612,614,615,616,631,632,633,636,663,664,665,669,670,671,672,674,695,699,700,704,721,724,725,726,751,755,756,757,780,782,783,784,785,787,788,792,793,795,822,823,824,826,827,831,859,863,864,867,871,873,874,876,881,882,883,887,891,895,896,897,901,902,903,907,912,913,914,917,923,926,927,930,931)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,1,19,1,1,2,33,1,1,2,11,4,1,1,1,1,12,3,1,1,10,1,1,1,20,4,1,2,64,2,1,2,1,1,5,4,1,4,1,2,3,1,1,2,3,1,1,2,7,4,1,3,8,1,1,3,1,3,11,3,1,1,1,4,6,3,1,2,19,1,1,3,19,3,1,3,1,4,1,4,11,2,1,2,11,4,1,1,30,1,1,1,18,2,1,1,1,4,1,2,41,4,1,4,11,2,1,4,20,3,1,3,8,1,1,2,1,2,1,4,26,1,1,1,7,2,1,1,15,1,1,3,27,1,1,4,1,1,1,2,21,4,1,4,17,3,1,1,25,4,1,1,23,2,1,1,1,2,1,4,1,2,27,1,1,2,1,4,28,4,1,3,4,2,1,2,5,1,1,4,4,4,1,1,4,1,1,4,5,1,1,3,6,3,1,3,1,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,0,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','EndArray','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Null','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','EndObject','Whitespace')
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{',' ','"Com\u0070a\u006ey"',' ',':','  ','"Pe\u0072miso\u0020Securi\u0074y"',' ',',','  ','"T\u0061gs"','    ',':',' ','[',' ','"Clo\u0075d"','   ',',',' ','"Identity"',' ',',',' ','"Sec\u0075\u0072ity"','    ',',','  ','"CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"','  ',']','  ',',',' ','"IDs"','    ',':','    ','[','  ','116',' ',',','  ','943',' ',',','  ','234.567','    ',',','   ','-38793.1',' ',']','   ',',','   ','"Tea\u006d"','   ',':',' ','{','    ','"Name"','   ',':','  ','"p\u0030 Lab\u0073"',' ',',','   ','"M\u0065m\u0062ers"','   ',':','   ','[','    ','{','    ','"FirstName"','  ',':','  ','"An\u0064i"','    ',',',' ','"\u004cast\u004e\u0061\u006de"',' ',':',' ','"A\u0068m\u0065ti"','  ','}',' ',',','    ','{','  ','"\u0046\u0069\u0072stN\u0061\u006d\u0065"','    ',':','    ','"M\u0065la"','  ',',','    ','"L\u0061stNa\u006de"','   ',':','   ','"Elezaj"',' ','}','  ',',','  ','{','    ','"Fi\u0072\u0073t\u004eame"',' ',':',' ','"Enisa"','  ',',',' ','"Last\u004eame"',' ',':','   ','"H\u006fxhaxhi\u006b\u0075"',' ','}','    ',',',' ','{','  ','"Firs\u0074Nam\u0065"','    ',':','    ','"A\u0062ia\u006e"','   ',',',' ','"\u004cas\u0074Nam\u0065"','    ',':',' ','"\u004d\u006f\u0072ina"','  ','}',' ',']','  ','}','    ',',','  ','"Mix\u0065\u0064Arra\u0079"',' ',':','  ','[','    ','"\u0073\u0074ri\u006e\u0067"','    ',',','   ','true','  ',',','  ','false',' ',',','    ','null','    ',',',' ','1337',' ',',','    ','13.37',' ',',','   ','-13.37','   ',']','   ','}',' ')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}

Describe 'ConvertTo-JsonObject -Target JsonTokenEnriched' -Tag 'ConvertTo-JsonObject','JsonTokenEnriched' {
    Context 'parsing JsonTokenEnriched tokens from policy (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonTokenEnriched
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 5
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,7,8,20)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,6,1,12,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject')
        }

        It 'should return Path.Content for all tokens' {
            $tokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,'Name','Name','Name',$null)
        }

        It 'should return Path.ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,'Name','Name','Name',$null)
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Name"',':','"SkyScalpel"','}')
        }

        It 'should return ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{','"Name"',':','"SkyScalpel"','}')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all tokens' {
            -join$tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonTokenEnriched tokens from policy (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonTokenEnriched
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 99
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,10,11,29,30,36,37,38,45,46,56,57,67,68,102,103,104,109,110,111,114,115,118,119,126,127,135,136,137,143,144,145,151,152,161,162,171,172,173,174,185,186,192,193,203,204,212,213,214,215,226,227,233,234,244,245,253,254,255,256,267,268,275,276,286,287,299,300,301,302,313,314,321,322,332,333,341,342,343,344,345,357,358,359,367,368,372,373,378,379,383,384,388,389,394,395,401,402)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,9,1,18,1,6,1,1,7,1,10,1,10,1,34,1,1,5,1,1,3,1,3,1,7,1,8,1,1,6,1,1,6,1,9,1,9,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,7,1,10,1,12,1,1,1,11,1,7,1,10,1,8,1,1,1,1,12,1,1,8,1,4,1,5,1,4,1,4,1,5,1,6,1,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,2,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','EndArray','EndObject','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Null','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','EndObject')
        }

        It 'should return Path.Content for all tokens' {
            $tokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,'Company','Company','Company',$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,'Team','Team','Team','Team.Name','Team.Name','Team.Name','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team',$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null)
        }

        It 'should return Path.ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,'Company','Company','Company',$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,'Team','Team','Team','Team.Name','Team.Name','Team.Name','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team',$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null)
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Company"',':','"Permiso Security"',',','"Tags"',':','[','"Cloud"',',','"Identity"',',','"Security"',',','"CDR (Cloud Detection & Response)"',']',',','"IDs"',':','[','116',',','943',',','234.567',',','-38793.1',']',',','"Team"',':','{','"Name"',':','"p0 Labs"',',','"Members"',':','[','{','"FirstName"',':','"Andi"',',','"LastName"',':','"Ahmeti"','}',',','{','"FirstName"',':','"Mela"',',','"LastName"',':','"Elezaj"','}',',','{','"FirstName"',':','"Enisa"',',','"LastName"',':','"Hoxhaxhiku"','}',',','{','"FirstName"',':','"Abian"',',','"LastName"',':','"Morina"','}',']','}',',','"MixedArray"',':','[','"string"',',','true',',','false',',','null',',','1337',',','13.37',',','-13.37',']','}')
        }

        It 'should return ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{','"Company"',':','"Permiso Security"',',','"Tags"',':','[','"Cloud"',',','"Identity"',',','"Security"',',','"CDR (Cloud Detection & Response)"',']',',','"IDs"',':','[','116',',','943',',','234.567',',','-38793.1',']',',','"Team"',':','{','"Name"',':','"p0 Labs"',',','"Members"',':','[','{','"FirstName"',':','"Andi"',',','"LastName"',':','"Ahmeti"','}',',','{','"FirstName"',':','"Mela"',',','"LastName"',':','"Elezaj"','}',',','{','"FirstName"',':','"Enisa"',',','"LastName"',':','"Hoxhaxhiku"','}',',','{','"FirstName"',':','"Abian"',',','"LastName"',':','"Morina"','}',']','}',',','"MixedArray"',':','[','"string"',',','true',',','false',',','null',',','1337',',','13.37',',','-13.37',']','}')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all tokens' {
            -join$tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonTokenEnriched tokens from policy (advanced)' -Tag 'advanced' {
        BeforeAll {
            $jsonDecoded = '{ "Company" :  "Permiso Security" ,  "Tags"    : [ "Cloud"   , "Identity" , "Security"    ,  "CDR (Cloud Detection & Response)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Team"   : {    "Name"   :  "p0 Labs" ,   "Members"   :   [    {    "FirstName"  :  "Andi"    , "LastName" : "Ahmeti"  } ,    {  "FirstName"    :    "Mela"  ,    "LastName"   :   "Elezaj" }  ,  {    "FirstName" : "Enisa"  , "LastName" :   "Hoxhaxhiku" }    , {  "FirstName"    :    "Abian"   , "LastName"    : "Morina"  } ]  }    ,  "MixedArray" :  [    "string"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
            $tokens = $json | ConvertTo-JsonObject -Target JsonTokenEnriched
        }

        It 'should return token count' {
            $tokens.Count | Should -BeExactly 198
        }

        It 'should return Start for all tokens' {
            $tokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,2,21,22,23,25,58,59,60,62,73,77,78,79,80,81,93,96,97,98,108,109,110,111,131,135,136,138,202,204,205,207,208,209,214,218,219,223,224,226,229,230,231,233,236,237,238,240,247,251,252,255,263,264,265,268,269,272,283,286,287,288,289,293,299,302,303,305,324,325,326,329,348,351,352,355,356,360,361,365,376,378,379,381,392,396,397,398,428,429,430,431,449,451,452,453,454,458,459,461,502,506,507,511,522,524,525,529,549,552,553,556,564,565,566,568,569,571,572,576,602,603,604,605,612,614,615,616,631,632,633,636,663,664,665,669,670,671,672,674,695,699,700,704,721,724,725,726,751,755,756,757,780,782,783,784,785,787,788,792,793,795,822,823,824,826,827,831,859,863,864,867,871,873,874,876,881,882,883,887,891,895,896,897,901,902,903,907,912,913,914,917,923,926,927,930,931)
        }

        It 'should return Length for all tokens' {
            $tokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,1,19,1,1,2,33,1,1,2,11,4,1,1,1,1,12,3,1,1,10,1,1,1,20,4,1,2,64,2,1,2,1,1,5,4,1,4,1,2,3,1,1,2,3,1,1,2,7,4,1,3,8,1,1,3,1,3,11,3,1,1,1,4,6,3,1,2,19,1,1,3,19,3,1,3,1,4,1,4,11,2,1,2,11,4,1,1,30,1,1,1,18,2,1,1,1,4,1,2,41,4,1,4,11,2,1,4,20,3,1,3,8,1,1,2,1,2,1,4,26,1,1,1,7,2,1,1,15,1,1,3,27,1,1,4,1,1,1,2,21,4,1,4,17,3,1,1,25,4,1,1,23,2,1,1,1,2,1,4,1,2,27,1,1,2,1,4,28,4,1,3,4,2,1,2,5,1,1,4,4,4,1,1,4,1,1,4,5,1,1,3,6,3,1,3,1,1)
        }

        It 'should return Depth for all tokens' {
            $tokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,0,0)
        }

        It 'should return Type (and potential SubType and Format) for all tokens' {
            $tokensTypeSubType = $tokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $tokensTypeSubType | Should -BeExactly @('BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','EndArray','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Null','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','EndObject','Whitespace')
        }

        It 'should return Path.Content for all tokens' {
            $tokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,$null,'Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey',$null,$null,$null,'T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs',$null,$null,$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,$null,$null,'Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d','Tea\u006d',$null,$null,$null,'Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079',$null,$null,$null)
        }

        It 'should return Path.ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,$null,'Company','Company','Company','Company','Company',$null,$null,$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,$null,$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,$null,$null,'Team','Team','Team','Team','Team','Team','Team.Name','Team.Name','Team.Name','Team.Name','Team.Name','Team','Team','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team','Team',$null,$null,$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null,$null,$null)
        }

        It 'should return Content for all tokens' {
            $tokens.ForEach( { $_.Content } ) | Should -BeExactly @('{',' ','"Com\u0070a\u006ey"',' ',':','  ','"Pe\u0072miso\u0020Securi\u0074y"',' ',',','  ','"T\u0061gs"','    ',':',' ','[',' ','"Clo\u0075d"','   ',',',' ','"Identity"',' ',',',' ','"Sec\u0075\u0072ity"','    ',',','  ','"CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"','  ',']','  ',',',' ','"IDs"','    ',':','    ','[','  ','116',' ',',','  ','943',' ',',','  ','234.567','    ',',','   ','-38793.1',' ',']','   ',',','   ','"Tea\u006d"','   ',':',' ','{','    ','"Name"','   ',':','  ','"p\u0030 Lab\u0073"',' ',',','   ','"M\u0065m\u0062ers"','   ',':','   ','[','    ','{','    ','"FirstName"','  ',':','  ','"An\u0064i"','    ',',',' ','"\u004cast\u004e\u0061\u006de"',' ',':',' ','"A\u0068m\u0065ti"','  ','}',' ',',','    ','{','  ','"\u0046\u0069\u0072stN\u0061\u006d\u0065"','    ',':','    ','"M\u0065la"','  ',',','    ','"L\u0061stNa\u006de"','   ',':','   ','"Elezaj"',' ','}','  ',',','  ','{','    ','"Fi\u0072\u0073t\u004eame"',' ',':',' ','"Enisa"','  ',',',' ','"Last\u004eame"',' ',':','   ','"H\u006fxhaxhi\u006b\u0075"',' ','}','    ',',',' ','{','  ','"Firs\u0074Nam\u0065"','    ',':','    ','"A\u0062ia\u006e"','   ',',',' ','"\u004cas\u0074Nam\u0065"','    ',':',' ','"\u004d\u006f\u0072ina"','  ','}',' ',']','  ','}','    ',',','  ','"Mix\u0065\u0064Arra\u0079"',' ',':','  ','[','    ','"\u0073\u0074ri\u006e\u0067"','    ',',','   ','true','  ',',','  ','false',' ',',','    ','null','    ',',',' ','1337',' ',',','    ','13.37',' ',',','   ','-13.37','   ',']','   ','}',' ')
        }

        It 'should return ContentDecoded for all tokens' {
            $tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{',' ','"Company"',' ',':','  ','"Permiso Security"',' ',',','  ','"Tags"','    ',':',' ','[',' ','"Cloud"','   ',',',' ','"Identity"',' ',',',' ','"Security"','    ',',','  ','"CDR (Cloud Detection & Response)"','  ',']','  ',',',' ','"IDs"','    ',':','    ','[','  ','116',' ',',','  ','943',' ',',','  ','234.567','    ',',','   ','-38793.1',' ',']','   ',',','   ','"Team"','   ',':',' ','{','    ','"Name"','   ',':','  ','"p0 Labs"',' ',',','   ','"Members"','   ',':','   ','[','    ','{','    ','"FirstName"','  ',':','  ','"Andi"','    ',',',' ','"LastName"',' ',':',' ','"Ahmeti"','  ','}',' ',',','    ','{','  ','"FirstName"','    ',':','    ','"Mela"','  ',',','    ','"LastName"','   ',':','   ','"Elezaj"',' ','}','  ',',','  ','{','    ','"FirstName"',' ',':',' ','"Enisa"','  ',',',' ','"LastName"',' ',':','   ','"Hoxhaxhiku"',' ','}','    ',',',' ','{','  ','"FirstName"','    ',':','    ','"Abian"','   ',',',' ','"LastName"','    ',':',' ','"Morina"','  ','}',' ',']','  ','}','    ',',','  ','"MixedArray"',' ',':','  ','[','    ','"string"','    ',',','   ','true','  ',',','  ','false',' ',',','    ','null','    ',',',' ','1337',' ',',','    ','13.37',' ',',','   ','-13.37','   ',']','   ','}',' ')
        }

        It 'should return re-concatenated Content for all tokens' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all tokens' {
            -join$tokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $jsonDecoded
        }
    }
}

Describe 'ConvertTo-JsonObject -Target JsonBranch' -Tag 'ConvertTo-JsonObject','JsonBranch' {
    Context 'parsing JsonBranch branches from policy (basic)' -Tag 'basic' {
        BeforeAll {
            $json = '{"Name":"SkyScalpel"}'
            $branches = $json | ConvertTo-JsonObject -Target JsonBranch
            $branchTokens = $branches | Expand-JsonObject
        }

        It 'should return branch count' {
            $branches.Count | Should -BeExactly 1
        }

        It 'should return branch length' {
            $branches.Length | Should -BeExactly 21
        }

        It 'should return branch depth' {
            $branches.Depth | Should -BeExactly -1
        }

        It 'should return branch max depth' {
            $branches.DepthMax | Should -BeExactly 1
        }

        It 'should return only JsonBranch object types' {
            $branches.GetType().Name | Should -BeExactly 'JsonBranch'
        }

        It 'should return Content for root branch' {
            $branches.Content | Should -BeExactly $json
        }

        It 'should return ContentDecoded for root branch' {
            $branches.ContentDecoded | Should -BeExactly $json
        }

        It 'should return only JsonTokenEnriched object types' {
            $branchTokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return expanded branch tokens count' {
            $branchTokens.Count | Should -BeExactly 5
        }

        It 'should return Start for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,7,8,20)
        }

        It 'should return Length for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,6,1,12,1)
        }

        It 'should return Depth for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all expanded branch tokens' {
            $branchTokensTypeSubType = $branchTokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $branchTokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject')
        }

        It 'should return Path.Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,'Name','Name','Name',$null)
        }

        It 'should return Path.ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,'Name','Name','Name',$null)
        }

        It 'should return Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Name"',':','"SkyScalpel"','}')
        }

        It 'should return ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{','"Name"',':','"SkyScalpel"','}')
        }

        It 'should return re-concatenated Content for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonBranch branches from policy (intermediate)' -Tag 'intermediate' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $branches = $json | ConvertTo-JsonObject -Target JsonBranch
            $branchTokens = $branches | Expand-JsonObject
        }

        It 'should return branch count' {
            $branches.Count | Should -BeExactly 1
        }

        It 'should return branch length' {
            $branches.Length | Should -BeExactly 403
        }

        It 'should return branch depth' {
            $branches.Depth | Should -BeExactly -1
        }

        It 'should return branch max depth' {
            $branches.DepthMax | Should -BeExactly 4
        }

        It 'should return only JsonBranch object types' {
            $branches.GetType().Name | Should -BeExactly 'JsonBranch'
        }

        It 'should return Content for root branch' {
            $branches.Content | Should -BeExactly $json
        }

        It 'should return ContentDecoded for root branch' {
            $branches.ContentDecoded | Should -BeExactly $json
        }

        It 'should return only JsonTokenEnriched object types' {
            $branchTokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return expanded branch tokens count' {
            $branchTokens.Count | Should -BeExactly 99
        }

        It 'should return Start for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,10,11,29,30,36,37,38,45,46,56,57,67,68,102,103,104,109,110,111,114,115,118,119,126,127,135,136,137,143,144,145,151,152,161,162,171,172,173,174,185,186,192,193,203,204,212,213,214,215,226,227,233,234,244,245,253,254,255,256,267,268,275,276,286,287,299,300,301,302,313,314,321,322,332,333,341,342,343,344,345,357,358,359,367,368,372,373,378,379,383,384,388,389,394,395,401,402)
        }

        It 'should return Length for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,9,1,18,1,6,1,1,7,1,10,1,10,1,34,1,1,5,1,1,3,1,3,1,7,1,8,1,1,6,1,1,6,1,9,1,9,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,6,1,10,1,8,1,1,1,11,1,7,1,10,1,12,1,1,1,11,1,7,1,10,1,8,1,1,1,1,12,1,1,8,1,4,1,5,1,4,1,4,1,5,1,6,1,1)
        }

        It 'should return Depth for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,1,1,1,1,1,2,2,2,2,2,2,2,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,3,3,4,4,4,4,4,4,4,3,2,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,1,0)
        }

        It 'should return Type (and potential SubType and Format) for all expanded branch tokens' {
            $branchTokensTypeSubType = $branchTokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $branchTokensTypeSubType | Should -BeExactly @('BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.String','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','ValueSeparator','BeginObject','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','ValueSeparator','Name.ObjectMember.String','NameSeparator','Value.ObjectMember.String','EndObject','EndArray','EndObject','ValueSeparator','Name.ObjectMember.String','NameSeparator','BeginArray','Value.ArrayElement.String','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Boolean','ValueSeparator','Value.ArrayElement.Null','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','ValueSeparator','Value.ArrayElement.Number','EndArray','EndObject')
        }

        It 'should return Path.Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,'Company','Company','Company',$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,'Team','Team','Team','Team.Name','Team.Name','Team.Name','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team',$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null)
        }

        It 'should return Path.ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,'Company','Company','Company',$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,'Team','Team','Team','Team.Name','Team.Name','Team.Name','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team',$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null)
        }

        It 'should return Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Content } ) | Should -BeExactly @('{','"Company"',':','"Permiso Security"',',','"Tags"',':','[','"Cloud"',',','"Identity"',',','"Security"',',','"CDR (Cloud Detection & Response)"',']',',','"IDs"',':','[','116',',','943',',','234.567',',','-38793.1',']',',','"Team"',':','{','"Name"',':','"p0 Labs"',',','"Members"',':','[','{','"FirstName"',':','"Andi"',',','"LastName"',':','"Ahmeti"','}',',','{','"FirstName"',':','"Mela"',',','"LastName"',':','"Elezaj"','}',',','{','"FirstName"',':','"Enisa"',',','"LastName"',':','"Hoxhaxhiku"','}',',','{','"FirstName"',':','"Abian"',',','"LastName"',':','"Morina"','}',']','}',',','"MixedArray"',':','[','"string"',',','true',',','false',',','null',',','1337',',','13.37',',','-13.37',']','}')
        }

        It 'should return ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{','"Company"',':','"Permiso Security"',',','"Tags"',':','[','"Cloud"',',','"Identity"',',','"Security"',',','"CDR (Cloud Detection & Response)"',']',',','"IDs"',':','[','116',',','943',',','234.567',',','-38793.1',']',',','"Team"',':','{','"Name"',':','"p0 Labs"',',','"Members"',':','[','{','"FirstName"',':','"Andi"',',','"LastName"',':','"Ahmeti"','}',',','{','"FirstName"',':','"Mela"',',','"LastName"',':','"Elezaj"','}',',','{','"FirstName"',':','"Enisa"',',','"LastName"',':','"Hoxhaxhiku"','}',',','{','"FirstName"',':','"Abian"',',','"LastName"',':','"Morina"','}',']','}',',','"MixedArray"',':','[','"string"',',','true',',','false',',','null',',','1337',',','13.37',',','-13.37',']','}')
        }

        It 'should return re-concatenated Content for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $json
        }
    }

    Context 'parsing JsonBranch branches from policy (advanced)' -Tag 'advanced' {
        BeforeAll {
            $jsonDecoded = '{ "Company" :  "Permiso Security" ,  "Tags"    : [ "Cloud"   , "Identity" , "Security"    ,  "CDR (Cloud Detection & Response)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Team"   : {    "Name"   :  "p0 Labs" ,   "Members"   :   [    {    "FirstName"  :  "Andi"    , "LastName" : "Ahmeti"  } ,    {  "FirstName"    :    "Mela"  ,    "LastName"   :   "Elezaj" }  ,  {    "FirstName" : "Enisa"  , "LastName" :   "Hoxhaxhiku" }    , {  "FirstName"    :    "Abian"   , "LastName"    : "Morina"  } ]  }    ,  "MixedArray" :  [    "string"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
            $json = '{ "Com\u0070a\u006ey" :  "Pe\u0072miso\u0020Securi\u0074y" ,  "T\u0061gs"    : [ "Clo\u0075d"   , "Identity" , "Sec\u0075\u0072ity"    ,  "CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"  ]  , "IDs"    :    [  116 ,  943 ,  234.567    ,   -38793.1 ]   ,   "Tea\u006d"   : {    "Name"   :  "p\u0030 Lab\u0073" ,   "M\u0065m\u0062ers"   :   [    {    "FirstName"  :  "An\u0064i"    , "\u004cast\u004e\u0061\u006de" : "A\u0068m\u0065ti"  } ,    {  "\u0046\u0069\u0072stN\u0061\u006d\u0065"    :    "M\u0065la"  ,    "L\u0061stNa\u006de"   :   "Elezaj" }  ,  {    "Fi\u0072\u0073t\u004eame" : "Enisa"  , "Last\u004eame" :   "H\u006fxhaxhi\u006b\u0075" }    , {  "Firs\u0074Nam\u0065"    :    "A\u0062ia\u006e"   , "\u004cas\u0074Nam\u0065"    : "\u004d\u006f\u0072ina"  } ]  }    ,  "Mix\u0065\u0064Arra\u0079" :  [    "\u0073\u0074ri\u006e\u0067"    ,   true  ,  false ,    null    , 1337 ,    13.37 ,   -13.37   ]   } '
            $branches = $json | ConvertTo-JsonObject -Target JsonBranch
            $branchTokens = $branches | Expand-JsonObject
        }

        It 'should return branch count' {
            $branches.Count | Should -BeExactly 1
        }

        It 'should return branch length' {
            $branches.Length | Should -BeExactly 932
        }

        It 'should return branch depth' {
            $branches.Depth | Should -BeExactly -1
        }

        It 'should return branch max depth' {
            $branches.DepthMax | Should -BeExactly 4
        }

        It 'should return only JsonBranch object types' {
            $branches.GetType().Name | Should -BeExactly 'JsonBranch'
        }

        It 'should return Content for root branch' {
            $branches.Content | Should -BeExactly $json
        }

        It 'should return ContentDecoded for root branch' {
            $branches.ContentDecoded | Should -BeExactly $jsonDecoded
        }

        It 'should return only JsonTokenEnriched object types' {
            $branchTokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return expanded branch tokens count' {
            $branchTokens.Count | Should -BeExactly 198
        }

        It 'should return Start for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Start } ) | Should -BeExactly @(0,1,2,21,22,23,25,58,59,60,62,73,77,78,79,80,81,93,96,97,98,108,109,110,111,131,135,136,138,202,204,205,207,208,209,214,218,219,223,224,226,229,230,231,233,236,237,238,240,247,251,252,255,263,264,265,268,269,272,283,286,287,288,289,293,299,302,303,305,324,325,326,329,348,351,352,355,356,360,361,365,376,378,379,381,392,396,397,398,428,429,430,431,449,451,452,453,454,458,459,461,502,506,507,511,522,524,525,529,549,552,553,556,564,565,566,568,569,571,572,576,602,603,604,605,612,614,615,616,631,632,633,636,663,664,665,669,670,671,672,674,695,699,700,704,721,724,725,726,751,755,756,757,780,782,783,784,785,787,788,792,793,795,822,823,824,826,827,831,859,863,864,867,871,873,874,876,881,882,883,887,891,895,896,897,901,902,903,907,912,913,914,917,923,926,927,930,931)
        }

        It 'should return Length for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Length } ) | Should -BeExactly @(1,1,19,1,1,2,33,1,1,2,11,4,1,1,1,1,12,3,1,1,10,1,1,1,20,4,1,2,64,2,1,2,1,1,5,4,1,4,1,2,3,1,1,2,3,1,1,2,7,4,1,3,8,1,1,3,1,3,11,3,1,1,1,4,6,3,1,2,19,1,1,3,19,3,1,3,1,4,1,4,11,2,1,2,11,4,1,1,30,1,1,1,18,2,1,1,1,4,1,2,41,4,1,4,11,2,1,4,20,3,1,3,8,1,1,2,1,2,1,4,26,1,1,1,7,2,1,1,15,1,1,3,27,1,1,4,1,1,1,2,21,4,1,4,17,3,1,1,25,4,1,1,23,2,1,1,1,2,1,4,1,2,27,1,1,2,1,4,28,4,1,3,4,2,1,2,5,1,1,4,4,4,1,1,4,1,1,4,5,1,1,3,6,3,1,3,1,1)
        }

        It 'should return Depth for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Depth } ) | Should -BeExactly @(0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,3,3,2,2,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,0,0)
        }

        It 'should return Type (and potential SubType and Format) for all expanded branch tokens' {
            $branchTokensTypeSubType = $branchTokens.ForEach( { @($_.Type,$_.SubType,$_.Format).Where( { $_ } ) -join '.' } )
            $branchTokensTypeSubType | Should -BeExactly @('BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.String','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','BeginObject','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','Value.ObjectMember.String','Whitespace','EndObject','Whitespace','EndArray','Whitespace','EndObject','Whitespace','ValueSeparator','Whitespace','Name.ObjectMember.String','Whitespace','NameSeparator','Whitespace','BeginArray','Whitespace','Value.ArrayElement.String','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Boolean','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Null','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','ValueSeparator','Whitespace','Value.ArrayElement.Number','Whitespace','EndArray','Whitespace','EndObject','Whitespace')
        }

        It 'should return Path.Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.Content } ) | Should -BeExactly @($null,$null,'Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey','Com\u0070a\u006ey',$null,$null,$null,'T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs','T\u0061gs',$null,$null,$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,$null,$null,'Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d.Name','Tea\u006d','Tea\u006d','Tea\u006d','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers.FirstName','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers.\u004cast\u004e\u0061\u006de','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers.\u0046\u0069\u0072stN\u0061\u006d\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers.L\u0061stNa\u006de','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers.Fi\u0072\u0073t\u004eame','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers.Last\u004eame','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.Firs\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers.\u004cas\u0074Nam\u0065','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d.M\u0065m\u0062ers','Tea\u006d','Tea\u006d',$null,$null,$null,'Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079','Mix\u0065\u0064Arra\u0079',$null,$null,$null)
        }

        It 'should return Path.ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Path.ContentDecoded } ) | Should -BeExactly @($null,$null,'Company','Company','Company','Company','Company',$null,$null,$null,'Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags','Tags',$null,$null,$null,'IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs','IDs',$null,$null,$null,'Team','Team','Team','Team','Team','Team','Team.Name','Team.Name','Team.Name','Team.Name','Team.Name','Team','Team','Team','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members.FirstName','Team.Members','Team.Members','Team.Members','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members.LastName','Team.Members','Team.Members','Team.Members','Team.Members','Team','Team',$null,$null,$null,'MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray','MixedArray',$null,$null,$null)
        }

        It 'should return Content for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.Content } ) | Should -BeExactly @('{',' ','"Com\u0070a\u006ey"',' ',':','  ','"Pe\u0072miso\u0020Securi\u0074y"',' ',',','  ','"T\u0061gs"','    ',':',' ','[',' ','"Clo\u0075d"','   ',',',' ','"Identity"',' ',',',' ','"Sec\u0075\u0072ity"','    ',',','  ','"CDR (Cloud\u0020D\u0065tecti\u006fn \u0026 Respo\u006es\u0065)"','  ',']','  ',',',' ','"IDs"','    ',':','    ','[','  ','116',' ',',','  ','943',' ',',','  ','234.567','    ',',','   ','-38793.1',' ',']','   ',',','   ','"Tea\u006d"','   ',':',' ','{','    ','"Name"','   ',':','  ','"p\u0030 Lab\u0073"',' ',',','   ','"M\u0065m\u0062ers"','   ',':','   ','[','    ','{','    ','"FirstName"','  ',':','  ','"An\u0064i"','    ',',',' ','"\u004cast\u004e\u0061\u006de"',' ',':',' ','"A\u0068m\u0065ti"','  ','}',' ',',','    ','{','  ','"\u0046\u0069\u0072stN\u0061\u006d\u0065"','    ',':','    ','"M\u0065la"','  ',',','    ','"L\u0061stNa\u006de"','   ',':','   ','"Elezaj"',' ','}','  ',',','  ','{','    ','"Fi\u0072\u0073t\u004eame"',' ',':',' ','"Enisa"','  ',',',' ','"Last\u004eame"',' ',':','   ','"H\u006fxhaxhi\u006b\u0075"',' ','}','    ',',',' ','{','  ','"Firs\u0074Nam\u0065"','    ',':','    ','"A\u0062ia\u006e"','   ',',',' ','"\u004cas\u0074Nam\u0065"','    ',':',' ','"\u004d\u006f\u0072ina"','  ','}',' ',']','  ','}','    ',',','  ','"Mix\u0065\u0064Arra\u0079"',' ',':','  ','[','    ','"\u0073\u0074ri\u006e\u0067"','    ',',','   ','true','  ',',','  ','false',' ',',','    ','null','    ',',',' ','1337',' ',',','    ','13.37',' ',',','   ','-13.37','   ',']','   ','}',' ')
        }

        It 'should return ContentDecoded for all expanded branch tokens' {
            $branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly @('{',' ','"Company"',' ',':','  ','"Permiso Security"',' ',',','  ','"Tags"','    ',':',' ','[',' ','"Cloud"','   ',',',' ','"Identity"',' ',',',' ','"Security"','    ',',','  ','"CDR (Cloud Detection & Response)"','  ',']','  ',',',' ','"IDs"','    ',':','    ','[','  ','116',' ',',','  ','943',' ',',','  ','234.567','    ',',','   ','-38793.1',' ',']','   ',',','   ','"Team"','   ',':',' ','{','    ','"Name"','   ',':','  ','"p0 Labs"',' ',',','   ','"Members"','   ',':','   ','[','    ','{','    ','"FirstName"','  ',':','  ','"Andi"','    ',',',' ','"LastName"',' ',':',' ','"Ahmeti"','  ','}',' ',',','    ','{','  ','"FirstName"','    ',':','    ','"Mela"','  ',',','    ','"LastName"','   ',':','   ','"Elezaj"',' ','}','  ',',','  ','{','    ','"FirstName"',' ',':',' ','"Enisa"','  ',',',' ','"LastName"',' ',':','   ','"Hoxhaxhiku"',' ','}','    ',',',' ','{','  ','"FirstName"','    ',':','    ','"Abian"','   ',',',' ','"LastName"','    ',':',' ','"Morina"','  ','}',' ',']','  ','}','    ',',','  ','"MixedArray"',' ',':','  ','[','    ','"string"','    ',',','   ','true','  ',',','  ','false',' ',',','    ','null','    ',',',' ','1337',' ',',','    ','13.37',' ',',','   ','-13.37','   ',']','   ','}',' ')
        }

        It 'should return re-concatenated Content for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }

        It 'should return re-concatenated ContentDecoded for all expanded branch tokens' {
            -join$branchTokens.ForEach( { $_.ContentDecoded } ) | Should -BeExactly $jsonDecoded
        }
    }
}