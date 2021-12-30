#function Get-IniFile
#
# Inspired by https://stackoverflow.com/questions/43690336/powershell-to-read-single-value-from-simple-ini-file
#

#{
    param(
        [parameter(Mandatory = $true)] [string] $filePath
    )

    $anonymous = "NoSection"

    $ini = @{}
    switch -regex -file $filePath
    {
        "^\[(.+)\]$" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }

        "^(;.*)$" # Comment
        {
            if (!($section))
            {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }

        "(.+?)\s*=\s*(.*)" # Key
        {
            if (!($section))
            {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }

    return $ini
#}
