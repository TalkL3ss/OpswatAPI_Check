$AllServers = @('http://server:port/')
function Send-TCPMessage { 
    Param ( 
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()] 
            [string] 
            $EndPoint
        , 
            [Parameter(Mandatory=$true, Position=1)]
            [int]
            $Port
        , 
            [Parameter(Mandatory=$true, Position=2)]
            [string]
            $Message
    ) 
    Process {
        # Setup connection 
        $IP = [System.Net.Dns]::GetHostAddresses($EndPoint) 
        $Address = [System.Net.IPAddress]::Parse($IP) 
        $Socket = New-Object System.Net.Sockets.TCPClient($Address,$Port) 
    
        # Setup stream wrtier 
        $Stream = $Socket.GetStream() 
        $Writer = New-Object System.IO.StreamWriter($Stream)

        # Write message to stream
        $Message | % {
            $Writer.WriteLine($_)
            $Writer.Flush()
        }
    
        # Close connection and stream
        $Stream.Close()
        $Socket.Close()
    }
}

function CreateTmpPNG {
    Add-Type -AssemblyName System.Drawing

    $tmpfilename = ".\tmp.png" 
    $bmp = new-object System.Drawing.Bitmap 100,30 
    $font = new-object System.Drawing.Font Consolas,10 
    $BodyBg = [System.Drawing.Brushes]::Black 
    $BodyFg = [System.Drawing.Brushes]::Red 
    $graphics = [System.Drawing.Graphics]::FromImage($bmp) 
    $graphics.FillRectangle($BodyBg,0,0,$bmp.Width,$bmp.Height) 
    $graphics.DrawString("OhadH"+("{0:d6}" -f (Get-Random -Minimum 1 -Maximum 9999999)),$font,$BodyFg,10,10) 
    $graphics.Dispose() 
    $bmp.Save($tmpfilename) 
    $tmpC = (gc $tmpfilename -Raw -Encoding Byte)
    rm $tmpfilename -Force -Confirm:$false
    return $tmpC
}

function SendFileToCDR {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()] 
        [string] 
        $ServerURI
    , 
        [Parameter(Mandatory=$false, Position=1)]
        [byte[]]
        $File = (CreateTmpPNG)
    ,
        [Parameter(Mandatory=$false, Position=2)]
        [string]
        $ruleName = 'myPolicy'
    )
    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = @{
        'rule' = $ruleName
        'filename' = 'ShobTestfile.png'
        'user_agent' = 'webscan'
        'Content-type' = 'application/json;charset=utf-8'
        'Accept'= 'application/json, text/plain, */*'
    }
    $shobFile = $File
    $firstScan = '{0}{1}' -f $ServerURI,'file'
    $SendFileToCDR = (Invoke-WebRequest -Uri $firstScan -Method Post -Headers $headers -Body $shobFile).Content
    Start-sleep -Seconds 10
    $ConverttedPath = '{0}{1}{2}' -f $ServerURI,'file/converted/',(($SendFileToCDR | ConvertFrom-Json).data_id)
    $RestContent = (Invoke-WebRequest -Uri $ConverttedPath).Content

    if ($RestContent.Length -gt 360) { $funcStat="CDR completed successfully!"} else {$funcStat="CDR has not completed successfully!"}
    $leefMessage = '{0} {1} {2}{3}{4}{5}{6}{7}' -f (Get-Date -Format "MMM dd HH:mm:ss"),($ServerURI.Split(".")[0]).split("/")[2],"`t|LEEF:1.0|Script|HealthCheck|1.0b`tsrc=",($ServerURI.Split(".")[0]).split("/")[2],"`tmsg=",$funcStat,"`tProfile=",$headers.rule
    Send-TCPMessage -Message $leefMessage -EndPoint syslog.ip.fqdn -Port 514
}

$AllServers | % { sendFileToCDR -ServerURI $_ }
