BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'Expand-JsonObject (String)' -Tag 'Expand-JsonObject','String' {
    Context 'expanding input JSON string into a single String' -Tag 'helper' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $jsonStr = $json | Expand-JsonObject
        }

        It 'should return String count' {
            $jsonStr.Count | Should -BeExactly 1
        }

        It 'should return only String object types' {
            $jsonStr.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'String'
        }

        It 'should return concatenated value for String' {
            -join$jsonStr | Should -BeExactly $json
        }
    }
}

Describe 'Expand-JsonObject (JsonToken)' -Tag 'Expand-JsonObject','JsonToken' {
    Context 'expanding input array of JsonToken objects into an array of JsonToken objects' -Tag 'helper' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonToken | Expand-JsonObject
        }

        It 'should return JsonToken count' {
            $tokens.Count | Should -BeExactly 99
        }

        It 'should return only JsonToken object types' {
            $tokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonToken'
        }

        It 'should return concatenated Content for all JsonToken objects' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}

Describe 'Expand-JsonObject (JsonTokenEnriched)' -Tag 'Expand-JsonObject','JsonTokenEnriched' {
    Context 'expanding input array of JsonTokenEnriched objects into an array of JsonTokenEnriched objects' -Tag 'helper' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonTokenEnriched | Expand-JsonObject
        }

        It 'should return JsonTokenEnriched count' {
            $tokens.Count | Should -BeExactly 99
        }

        It 'should return only JsonTokenEnriched object types' {
            $tokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return concatenated Content for all JsonTokenEnriched objects' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}

Describe 'Expand-JsonObject (JsonBranch)' -Tag 'Expand-JsonObject','JsonBranch' {
    Context 'expanding input array of JsonBranch objects into an array of JsonTokenEnriched objects' -Tag 'helper' {
        BeforeAll {
            $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
            $tokens = $json | ConvertTo-JsonObject -Target JsonBranch | Expand-JsonObject
        }

        It 'should return JsonTokenEnriched count' {
            $tokens.Count | Should -BeExactly 99
        }

        It 'should return only JsonTokenEnriched object types' {
            $tokens.ForEach( { $_.GetType().Name } ) | Sort-Object -Unique | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return concatenated Content for all JsonTokenEnriched objects' {
            -join$tokens.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}