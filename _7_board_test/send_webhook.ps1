# 1. 프로덕션용 (환경변수 N8N_WEBHOOK_URL 우선 사용)
$uri = if ($env:N8N_WEBHOOK_URL) { $env:N8N_WEBHOOK_URL } else { "http://localhost:5678/webhook/<your-webhook-id>" }

# ※ 만약 n8n 화면에서 'Listen for test event' 누르고 1회성 테스트 중이라면:
# $uri = "http://localhost:5678/webhook-test/<your-webhook-id>"


$headers = @{
    "Content-Type" = "application/json; charset=utf-8"
}

$body = @{
    ip       = "1.2.3.4"
    level    = 10
    rule     = "5712"
    severity = "High"
} | ConvertTo-Json -Compress

# UTF-8 바이트 배열로 명시적 변환하여 전송 안정성 확보
$utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($body)

try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $utf8Bytes
    Write-Host "전송 성공!" -ForegroundColor Green
    $response
} catch {
    Write-Host "전송 실패:" -ForegroundColor Red
    $_.Exception.Message
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $reader.ReadToEnd()
    }
}