param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8766
)

$ErrorActionPreference = 'Stop'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)

try {
    $listener.Start()
    Write-Host "LinkScope TCP-приёмник слушает порт $Port. Остановить: Ctrl+C" -ForegroundColor Cyan
    while ($true) {
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000
            $hello = [System.Text.Encoding]::ASCII.GetBytes("LINKSCOPE-READY`n")
            $stream.Write($hello, 0, $hello.Length)
            $stream.Flush()
            $commandBuffer = New-Object byte[] 32
            $commandLength = $stream.Read($commandBuffer, 0, $commandBuffer.Length)
            $command = [System.Text.Encoding]::ASCII.GetString($commandBuffer, 0, $commandLength).Trim()
            if ($command -eq 'PROBE') {
                $probeReply = [System.Text.Encoding]::ASCII.GetBytes('OK')
                $stream.Write($probeReply, 0, $probeReply.Length)
                $stream.Flush()
                continue
            }
            if ($command -ne 'START') { continue }
            $ready = [System.Text.Encoding]::ASCII.GetBytes('GO')
            $stream.Write($ready, 0, $ready.Length)
            $stream.Flush()
            $buffer = New-Object byte[] 65536
            [long]$totalBytes = 0
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            while ($true) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                $totalBytes += $read
            }
            $timer.Stop()
            $seconds = [Math]::Max($timer.Elapsed.TotalSeconds, 0.001)
            $mbps = [Math]::Round(($totalBytes * 8 / $seconds) / 1000000, 2)
            $ack = [System.Text.Encoding]::ASCII.GetBytes("OK $totalBytes")
            $stream.Write($ack, 0, $ack.Length)
            $stream.Flush()
            Write-Host ("{0} · {1:N2} МБ · {2:N2} Мбит/с" -f (Get-Date -Format 'HH:mm:ss'), ($totalBytes / 1MB), $mbps) -ForegroundColor Green
        }
        catch {
            Write-Warning "Соединение завершилось с ошибкой: $($_.Exception.Message)"
        }
        finally {
            if ($stream) { $stream.Dispose(); $stream = $null }
            $client.Dispose()
        }
    }
}
finally {
    $listener.Stop()
}
