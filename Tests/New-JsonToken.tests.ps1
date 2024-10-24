BeforeAll {
    Import-Module ./SkyScalpel.psd1
}

Describe 'New-JsonToken (JsonToken)' -Tag 'New-JsonToken','JsonToken' {
    Context 'creating JsonToken object' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $token = New-JsonToken -Content $content -Type $type
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }

    Context 'creating JsonToken object (with -Start and -Depth)' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $start = 133
            $depth = 7
            $token = New-JsonToken -Content $content -Type $type -Start $start -Depth $depth
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly $start
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly $depth
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }

    Context 'creating JsonToken object (with -SubType)' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $subType = [SkyScalpel.JsonTokenSubType]::ArrayElement
            $token = New-JsonToken -Content $content -Type $type -SubType $subType
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $null
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }

    Context 'creating JsonToken object (with -Format)' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $format = [SkyScalpel.JsonTokenFormat]::String
            $token = New-JsonToken -Content $content -Type $type -Format $format
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $null
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }

    Context 'creating JsonToken object (without -SubType and -Format)' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $token = New-JsonToken -Content $content -Type $type
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $null
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $null
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }

    Context 'creating JsonToken object (with -SubType, -Format, -Start and -Depth)' -Tag 'helper' {
        BeforeAll {
            $content = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $subType = [SkyScalpel.JsonTokenSubType]::ArrayElement
            $format = [SkyScalpel.JsonTokenFormat]::String
            $start = 133
            $depth = 7
            $token = New-JsonToken -Content $content -Type $type -SubType $subType -Format $format -Start $start -Depth $depth
        }

        It 'should return JsonToken count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonToken object type' {
            $token.GetType().Name | Should -BeExactly 'JsonToken'
        }

        It 'should return Start for JsonToken' {
            $token.Start | Should -BeExactly $start
        }

        It 'should return Length for JsonToken' {
            $token.Length | Should -BeExactly 6
        }

        It 'should return Depth for JsonToken' {
            $token.Depth | Should -BeExactly $depth
        }

        It 'should return Type for JsonToken' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonToken' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonToken' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return Content for JsonToken' {
            $token.Content | Should -BeExactly $content
        }
    }
}

Describe 'New-JsonToken (JsonTokenEnriched)' -Tag 'New-JsonToken','JsonTokenEnriched' {
    Context 'creating JsonTokenEnriched object' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $token = New-JsonToken -Content $content -Type $type -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }

    Context 'creating JsonTokenEnriched object (with -Start and -Depth)' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $start = 133
            $depth = 7
            $token = New-JsonToken -Content $content -Type $type -Start $start -Depth $depth -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly $start
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly $depth
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }

    Context 'creating JsonTokenEnriched object (with -SubType)' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $subType = [SkyScalpel.JsonTokenSubType]::ArrayElement
            $token = New-JsonToken -Content $content -Type $type -SubType $subType -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $null
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }

    Context 'creating JsonTokenEnriched object (with -Format)' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $format = [SkyScalpel.JsonTokenFormat]::String
            $token = New-JsonToken -Content $content -Type $type -Format $format -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $null
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }

    Context 'creating JsonTokenEnriched object (without -SubType and -Format)' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $token = New-JsonToken -Content $content -Type $type -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly -1
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly 0
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $null
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $null
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }

    Context 'creating JsonTokenEnriched object (with -SubType, -Format, -Start and -Depth)' -Tag 'helper' {
        BeforeAll {
            $content = 'A\u0063tion'
            $contentDecoded = 'Action'
            $type = [SkyScalpel.JsonTokenType]::Name
            $subType = [SkyScalpel.JsonTokenSubType]::ArrayElement
            $format = [SkyScalpel.JsonTokenFormat]::String
            $start = 133
            $depth = 7
            $token = New-JsonToken -Content $content -Type $type -SubType $subType -Format $format -Start $start -Depth $depth -Target JsonTokenEnriched
        }

        It 'should return JsonTokenEnriched count' {
            $token.Count | Should -BeExactly 1
        }

        It 'should return only JsonTokenEnriched object type' {
            $token.GetType().Name | Should -BeExactly 'JsonTokenEnriched'
        }

        It 'should return Start for JsonTokenEnriched' {
            $token.Start | Should -BeExactly $start
        }

        It 'should return Length for JsonTokenEnriched' {
            $token.Length | Should -BeExactly 11
        }

        It 'should return Depth for JsonTokenEnriched' {
            $token.Depth | Should -BeExactly $depth
        }

        It 'should return Type for JsonTokenEnriched' {
            $token.Type | Should -BeExactly $type
        }

        It 'should return SubType for JsonTokenEnriched' {
            $token.SubType | Should -BeExactly $subType
        }

        It 'should return Format for JsonTokenEnriched' {
            $token.Format | Should -BeExactly $format
        }

        It 'should return JsonTokenEnriched content' {
            $token.Content | Should -BeExactly $content
        }

        It 'should return ContentDecoded for JsonToken' {
            $token.ContentDecoded | Should -BeExactly $contentDecoded
        }
    }
}