#Source: https://twitter.com/terrajobst/status/1066915423344451584?s=03

Set-Alias less "C:\Users\Krzysztof\AppData\Local\Programs\Git\usr\bin\less.exe"

function f($text, $files="*.*")
{
    findstr /spin $text $files | less
}