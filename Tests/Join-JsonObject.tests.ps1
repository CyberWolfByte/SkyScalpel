BeforeAll {
    Import-Module ./SkyScalpel.psd1
}


Describe 'Join-JsonObject (String)' -Tag 'Join-JsonObject','String' {
    BeforeAll {
        $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        $jsonStr = $json
    }

    Context 'converting input JSON string into a single ArrayList' -Tag 'helper' {
        BeforeAll {
            $jsonStrArr = [System.Collections.ArrayList]::new()
            $jsonStrArr = Join-JsonObject -InputObject $jsonStr -InputObjectArray $jsonStrArr
        }

        It 'should return String count' {
            $jsonStrArr.Count | Should -BeExactly 1
        }

        It 'should return concatenated value for String' {
            -join$jsonStrArr | Should -BeExactly $json
        }
    }
}

Describe 'Join-JsonObject (JsonToken)' -Tag 'Join-JsonObject','JsonToken' {
    BeforeAll {
        $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        $tokens = $json | ConvertTo-JsonObject -Target JsonToken
    }

    Context 'converting input array of JsonToken objects into a single ArrayList via pipeline' -Tag 'helper' {
        BeforeAll {
            $tokenArr = [System.Collections.ArrayList]::new()
            $tokenArr = Join-JsonObject -InputObject $tokens -InputObjectArray $tokenArr
        }

        It 'should return JsonToken count' {
            $tokenArr.Count | Should -BeExactly 99
        }

        It 'should return concatenated Content for all JsonToken objects' {
            -join$tokenArr.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }

    Context 'converting input array of JsonToken objects into a single ArrayList via loop' -Tag 'helper' {
        BeforeAll {
            $tokenArr = [System.Collections.ArrayList]::new()
            foreach ($token in $tokens)
            {
                $tokenArr = Join-JsonObject -InputObject $token -InputObjectArray $tokenArr
            }
        }

        It 'should return JsonToken count' {
            $tokenArr.Count | Should -BeExactly 99
        }

        It 'should return concatenated Content for all JsonToken objects' {
            -join$tokenArr.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}

Describe 'Join-JsonObject (JsonTokenEnriched)' -Tag 'Join-JsonObject','JsonTokenEnriched' {
    BeforeAll {
        $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        $tokens = $json | ConvertTo-JsonObject -Target JsonTokenEnriched
    }

    Context 'converting input array of JsonTokenEnriched objects into a single ArrayList via pipeline' -Tag 'helper' {
        BeforeAll {
            $tokenArr = [System.Collections.ArrayList]::new()
            $tokenArr = Join-JsonObject -InputObject $tokens -InputObjectArray $tokenArr
        }

        It 'should return JsonTokenEnriched count' {
            $tokenArr.Count | Should -BeExactly 99
        }

        It 'should return concatenated Content for all JsonTokenEnriched objects' {
            -join$tokenArr.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }

    Context 'converting input array of JsonTokenEnriched objects into a single ArrayList via loop' -Tag 'helper' {
        BeforeAll {
            $tokenArr = [System.Collections.ArrayList]::new()
            foreach ($token in $tokens)
            {
                $tokenArr = Join-JsonObject -InputObject $token -InputObjectArray $tokenArr
            }
        }

        It 'should return JsonTokenEnriched count' {
            $tokenArr.Count | Should -BeExactly 99
        }

        It 'should return concatenated Content for all JsonTokenEnriched objects' {
            -join$tokenArr.ForEach( { $_.Content } ) | Should -BeExactly $json
        }
    }
}

Describe 'Join-JsonObject (JsonBranch)' -Tag 'Join-JsonObject','JsonBranch' {
    BeforeAll {
        $json = '{"Company":"Permiso Security","Tags":["Cloud","Identity","Security","CDR (Cloud Detection & Response)"],"IDs":[116,943,234.567,-38793.1],"Team":{"Name":"p0 Labs","Members":[{"FirstName":"Andi","LastName":"Ahmeti"},{"FirstName":"Mela","LastName":"Elezaj"},{"FirstName":"Enisa","LastName":"Hoxhaxhiku"},{"FirstName":"Abian","LastName":"Morina"}]},"MixedArray":["string",true,false,null,1337,13.37,-13.37]}'
        $branches = $json | ConvertTo-JsonObject -Target JsonBranch
    }

    Context 'converting input array of JsonBranch objects into a single ArrayList via pipeline' -Tag 'helper' {
        BeforeAll {
            $branchArr = [System.Collections.ArrayList]::new()
            $branchArr = Join-JsonObject -InputObject $branches -InputObjectArray $branchArr
        }

        It 'should return JsonBranch count' {
            $branchArr.Count | Should -BeExactly 1
        }

        It 'should return JsonBranch Branch count' {
            $branches.Branch.Count | Should -BeExactly 1
        }

        It 'should return Content for entire JsonBranch branch' {
            $branchArr.Content | Should -BeExactly $json
        }
    }

    Context 'converting input array of JsonBranch objects into a single ArrayList via loop' -Tag 'helper' {
        BeforeAll {
            $branchArr = [System.Collections.ArrayList]::new()
            foreach ($token in $branches)
            {
                $branchArr = Join-JsonObject -InputObject $token -InputObjectArray $branchArr
            }
        }

        It 'should return JsonBranch count' {
            $branchArr.Count | Should -BeExactly 1
        }

        It 'should return JsonBranch Branch count' {
            $branches.Branch.Count | Should -BeExactly 1
        }

        It 'should return Content for entire JsonBranch branch' {
            $branchArr.Content | Should -BeExactly $json
        }
    }
}