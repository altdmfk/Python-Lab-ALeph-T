# ==========================================================
# 과제 4 — 보안 이벤트 REST API 테스트 스크립트
# 1) POST /api/security/events (X-API-Key 인증 + 이벤트 생성)
# 2) GET /api/security/events?student=<이름> (기록 확인)
# ==========================================================

$baseUrl = if ($env:BOARD_URL) { $env:BOARD_URL } else { "http://localhost:5000" }
$apiKey  = if ($env:SECURITY_API_KEY) { $env:SECURITY_API_KEY } else { "<YOUR_SECURITY_API_KEY>" }
$student = if ($env:STUDENT_NAME) { $env:STUDENT_NAME } else { "강아름" }


$headers = @{
    "Content-Type" = "application/json; charset=utf-8"
    "X-API-Key"    = $apiKey
}

# 1. POST 보안 이벤트 전송 (로그인 차단 이벤트 예시)
$bodyObj = @{
    student      = $student
    src_ip       = "192.168.1.50"
    fail_count   = 5
    decision     = "deny"
    severity     = "High"
    reason       = "로그인 5회 실패로 인한 차단"
    users        = "admin, root"
    last_seen    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    window_min   = 10
    source       = "login_guard"
    generated_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

$jsonBody = $bodyObj | ConvertTo-Json -Compress
$utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[1] POST /api/security/events 요청 전송..." -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

try {
    $postRes = Invoke-RestMethod -Uri "$baseUrl/api/security/events" -Method Post -Headers $headers -Body $utf8Bytes
    Write-Host "POST 성공! (201 Created)" -ForegroundColor Green
    $postRes | Format-List
} catch {
    Write-Host "POST 실패:" -ForegroundColor Red
    $_.Exception.Message
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        Write-Host $reader.ReadToEnd() -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "[2] GET /api/security/events?student=$student 조회..." -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

try {
    # GET 요청은 인증 헤더(X-API-Key) 없이 호출
    $getRes = Invoke-RestMethod -Uri "$baseUrl/api/security/events?student=$student" -Method Get
    Write-Host "GET 성공! 총 $($getRes.count)건 조회됨" -ForegroundColor Green
    $getRes.events | Format-Table -Property id, student, src_ip, fail_count, decision, severity, reason, created_at
} catch {
    Write-Host "GET 실패:" -ForegroundColor Red
    $_.Exception.Message
}
