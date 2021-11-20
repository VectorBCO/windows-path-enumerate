Function External-Function {
    Write-Host "External function"
    return 'External'
}

Describe "Description" {
    Function Describe-Function {
        Write-Host "Describe function"
        return 'Describe'
    }
    It ExtFunction {
        External-Function | Should -be 'External'
    }
    It DescFunction {
        Describe-Function | Should -be 'Describe'
    }
}