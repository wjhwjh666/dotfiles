#Requires -Version 5.1
<#
.SYNOPSIS
    官方 Claude 账号防误封 —— 一键体检 + 修复（幂等，可反复跑）

.DESCRIPTION
    覆盖 2026-09-01 体检出的全部风险项：
      R1 Shell 配置常驻注入 ANTHROPIC_BASE_URL/AUTH_TOKEN 改道中转
      R2 用户环境变量（注册表 HKCU\Environment）里的 Anthropic 中转残留
      R3 .claude 下含中转配置的 settings 备份（随时可能被复原）
      R4 桌面端 remoteSessionFolderGrants 授权到 WindowsApps（客户端包目录）
      R5 全局代理覆盖 api.anthropic.com（共享出口 IP / 中途跳节点）
      R6 明文 API Key 散落在配置文件里
    所有写操作前自动备份；-DryRun 只报不改。

.PARAMETER DryRun
    只体检不修改。

.PARAMETER PinAnthropicDirect
    把 api.anthropic.com 等官方域名加入 NO_PROXY + 注册表 ProxyOverride，让官方流量绕开
    机场出口走本地直连。**仅在脚本的直连探测通过、且你确认拔了代理仍能用 Claude 时才加这个开关。**

.PARAMETER InstallWeeklyCheck
    注册一个每周日 10:00 的计划任务，用 -DryRun 模式自动复查并写日志（防配置回潮）。

.EXAMPLE
    pwsh -File Fix-ClaudeBanRisk.ps1 -DryRun
.EXAMPLE
    pwsh -File Fix-ClaudeBanRisk.ps1
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$PinAnthropicDirect,
    [switch]$InstallWeeklyCheck
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$Stamp        = Get-Date -Format 'yyyyMMdd-HHmmss'
$Tag          = Get-Date -Format 'yyyy-MM-dd'
$ClaudeHome   = Join-Path $env:USERPROFILE '.claude'
$Quarantine   = Join-Path $ClaudeHome ("attic\relay-quarantine-{0}" -f (Get-Date -Format 'yyyyMMdd'))
$LogDir       = Join-Path $ClaudeHome 'logs'
$LogFile      = Join-Path $LogDir "ban-risk-$Stamp.log"
$OfficialHost = 'api.anthropic.com'
$Manual       = New-Object System.Collections.Generic.List[string]
$Fixed        = New-Object System.Collections.Generic.List[string]

foreach ($d in @($LogDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

function Log {
    param([string]$Msg, [ValidateSet('ok','fix','warn','err','info')][string]$Level = 'info')
    $color = @{ ok='Green'; fix='Cyan'; warn='Yellow'; err='Red'; info='Gray' }[$Level]
    $mark  = @{ ok='[ OK ]'; fix='[ 修复 ]'; warn='[ 注意 ]'; err='[ 危险 ]'; info='      ' }[$Level]
    Write-Host "$mark $Msg" -ForegroundColor $color
    Add-Content -LiteralPath $LogFile -Value "$mark $Msg" -Encoding UTF8
}
function Section { param([string]$T) Write-Host ""; Write-Host "== $T ==" -ForegroundColor White; Add-Content -LiteralPath $LogFile -Value "`n== $T ==" -Encoding UTF8 }
function Backup-File {
    param([string]$Path)
    $bak = "$Path.banfix-$Stamp.bak"
    Copy-Item -LiteralPath $Path -Destination $bak -Force
    return $bak
}
function Mask { param([string]$S) if ($S.Length -le 12) { '***' } else { $S.Substring(0,10) + '...' + $S.Substring($S.Length-4) } }

Log "防误封体检开始  $(Get-Date -Format 'u')  DryRun=$DryRun" 'info'
Log "日志：$LogFile" 'info'

# ---------------------------------------------------------------- R1 Shell 配置
Section 'R1  Shell 配置里的 Anthropic 改道注入'

$profileCandidates = @(
    (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\profile.ps1'),
    (Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE 'Documents\PowerShell\profile.ps1'),
    (Join-Path $env:USERPROFILE 'OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE 'OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE '.bashrc'),
    (Join-Path $env:USERPROFILE '.bash_profile'),
    (Join-Path $env:USERPROFILE '.profile'),
    (Join-Path $env:USERPROFILE '.zshrc')
) | Where-Object { Test-Path $_ } | Select-Object -Unique

# 只打不在函数体里的“裸赋值”：函数内的按需开关是允许的
$assignRe = '^\s*(\$env:|export\s+)ANTHROPIC_(BASE_URL|AUTH_TOKEN|API_KEY)\s*='

foreach ($p in $profileCandidates) {
    $lines = Get-Content -LiteralPath $p -Encoding UTF8
    $depth = 0; $hits = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match $assignRe -and $depth -le 0) {
            # 值本身就是官方域名的放行
            if ($l -match [regex]::Escape($OfficialHost)) { continue }
            $hits += $i
        }
        $depth += ([regex]::Matches($l, '\{')).Count - ([regex]::Matches($l, '\}')).Count
    }
    if ($hits.Count -eq 0) { Log "干净：$p" 'ok'; continue }

    Log "$p 有 $($hits.Count) 处常驻改道注入（会让该 shell 起的 claude CLI 静默走中转）" 'err'
    foreach ($i in $hits) { Log "    L$($i+1): $($lines[$i].Trim())" 'info' }
    if ($DryRun) { $Manual.Add("注释掉 $p 的 $($hits.Count) 处 ANTHROPIC_* 裸赋值"); continue }

    $bak = Backup-File $p
    foreach ($i in $hits) { $lines[$i] = "# [ban-risk $Tag] " + $lines[$i] }
    $enc = if ($p -like '*.ps1') { 'UTF8' } else { 'UTF8' }   # PS5.1 的 UTF8 带 BOM，.ps1 需要
    if ($p -like '*.ps1') { Set-Content -LiteralPath $p -Value $lines -Encoding UTF8 }
    else { [IO.File]::WriteAllLines($p, $lines, (New-Object Text.UTF8Encoding($false))) }
    Log "已注释掉 $($hits.Count) 行，备份 $bak" 'fix'
    $Fixed.Add("$p 改道注入已注释")
}

# ---------------------------------------------------------------- R2 注册表环境变量
Section 'R2  用户环境变量中的 Anthropic 残留'

$envKey = 'HKCU:\Environment'
$envProps = Get-ItemProperty -Path $envKey
foreach ($n in 'ANTHROPIC_BASE_URL','ANTHROPIC_AUTH_TOKEN','ANTHROPIC_API_KEY') {
    $v = $envProps.$n
    if (-not $v) { Log "未设置：$n" 'ok'; continue }
    if ($n -eq 'ANTHROPIC_BASE_URL' -and $v -match [regex]::Escape($OfficialHost)) { Log "$n = $v（官方，保留）" 'ok'; continue }
    Log "$n = $(Mask $v)  → 会覆盖官方 OAuth，属高危" 'err'
    if ($DryRun) { $Manual.Add("删除用户环境变量 $n"); continue }
    Add-Content -LiteralPath $LogFile -Value "  备份原值 $n=$v" -Encoding UTF8
    Remove-ItemProperty -Path $envKey -Name $n -Force
    Log "已删除用户环境变量 $n（原值已记入日志，可回滚）" 'fix'
    $Fixed.Add("删除环境变量 $n")
}

# ---------------------------------------------------------------- R3 中转配置残留
Section 'R3  .claude 下含中转配置的 settings 文件'

$suspects = Get-ChildItem -LiteralPath $ClaudeHome -Recurse -File -Filter 'settings*' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "*\attic\relay-quarantine-*" -and $_.Length -lt 200KB } |
    Where-Object {
        $t = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        $t -and $t -match 'ANTHROPIC_(BASE_URL|AUTH_TOKEN)' -and $t -notmatch [regex]::Escape($OfficialHost)
    }

if (-not $suspects) { Log "没有发现含中转配置的 settings 文件" 'ok' }
foreach ($s in $suspects) {
    $isLive = ($s.Name -eq 'settings.json' -or $s.Name -eq 'settings.local.json')
    if ($isLive) {
        Log "生效中的 $($s.FullName) 含中转配置" 'err'
        if ($DryRun) { $Manual.Add("从 $($s.FullName) 剔除 ANTHROPIC_* 键"); continue }
        $bak = Backup-File $s.FullName
        $json = Get-Content -LiteralPath $s.FullName -Raw | ConvertFrom-Json
        if ($json.env) {
            foreach ($k in @($json.env.PSObject.Properties.Name)) {
                if ($k -like 'ANTHROPIC_*') { $json.env.PSObject.Properties.Remove($k) }
            }
        }
        $json | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $s.FullName -Encoding UTF8
        Log "已剔除 ANTHROPIC_* 键，备份 $bak" 'fix'
        $Fixed.Add("清理 $($s.Name)")
    } else {
        Log "备份文件 $($s.FullName) 含中转配置（复原即中招）" 'warn'
        if ($DryRun) { $Manual.Add("隔离 $($s.Name)"); continue }
        if (-not (Test-Path $Quarantine)) { New-Item -ItemType Directory -Path $Quarantine -Force | Out-Null }
        Move-Item -LiteralPath $s.FullName -Destination (Join-Path $Quarantine $s.Name) -Force
        Log "已隔离到 $Quarantine" 'fix'
        $Fixed.Add("隔离 $($s.Name)")
    }
}

# ---------------------------------------------------------------- R4 桌面端授权
Section 'R4  桌面端 remoteSessionFolderGrants 高危授权'

$cfgCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json'),
    (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'),
    (Join-Path $env:LOCALAPPDATA 'Claude-3p\claude_desktop_config.json')
) | Where-Object { Test-Path $_ }

if (-not $cfgCandidates) { Log "未找到桌面端配置（Cowork 未安装或路径又搬家了）" 'warn' }
foreach ($cfg in $cfgCandidates) {
    $j = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
    $grants = $j.preferences.remoteSessionFolderGrants
    if (-not $grants) { Log "无 remoteSessionFolderGrants：$cfg" 'ok'; continue }
    $bad = @()
    foreach ($sess in $grants.PSObject.Properties) {
        foreach ($path in @($sess.Value)) {
            if ($path -match 'WindowsApps|Packages\\Claude_|Program Files\\WindowsApps') { $bad += "$($sess.Name) -> $path" }
        }
    }
    if (-not $bad) { Log "授权清单干净：$cfg" 'ok'; continue }
    Log "$cfg 存在指向客户端包目录的会话授权（读改 app.asar 属高危信号）：" 'warn'
    $bad | ForEach-Object { Log "    $_" 'info' }
    if ($DryRun) { $Manual.Add("撤销 $cfg 里 $($bad.Count) 条 WindowsApps 授权"); continue }

    $proc = Get-Process -Name 'Claude' -ErrorAction SilentlyContinue
    if ($proc) { Log "Claude 桌面端正在运行，退出后再改否则会被覆写 —— 本项跳过" 'warn'; $Manual.Add("关闭 Claude 桌面端后重跑脚本以撤销 WindowsApps 授权"); continue }

    $bak = Backup-File $cfg
    foreach ($sess in @($grants.PSObject.Properties)) {
        $kept = @($sess.Value | Where-Object { $_ -notmatch 'WindowsApps|Packages\\Claude_' })
        if ($kept.Count -eq 0) { $grants.PSObject.Properties.Remove($sess.Name) }
        else { $grants.($sess.Name) = $kept }
    }
    $j | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $cfg -Encoding UTF8
    Log "已撤销，备份 $bak" 'fix'
    $Fixed.Add("撤销桌面端 WindowsApps 授权")
}

# ---------------------------------------------------------------- R5 代理路由
Section 'R5  代理路由（官方流量的出口 IP）'

$isKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$isProps  = Get-ItemProperty -Path $isKey
$proxyOn  = [int]$isProps.ProxyEnable -eq 1
$proxySrv = $isProps.ProxyServer
$override = [string]$isProps.ProxyOverride
$noProxy  = [string](Get-ItemProperty -Path $envKey).NO_PROXY

Log "系统代理：$(if($proxyOn){"启用 $proxySrv"}else{'未启用'})" 'info'
$covered = -not ($override -match 'anthropic' -or $noProxy -match 'anthropic')
if ($proxyOn -and $covered) {
    Log "api.anthropic.com 走代理出口 —— 共享 IP / 会话中途跳节点是误封头号诱因" 'err'
} elseif ($proxyOn) {
    Log "官方域名已在绕行名单中" 'ok'
} else {
    Log "无系统代理，官方流量走本地出口" 'ok'
}

# 直连探测：纯 TCP 握手，不请求任何回显自身 IP 的服务
function Test-Direct {
    param([string]$H, [int]$Port = 443, [int]$TimeoutMs = 5000)
    $c = New-Object Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($H, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($ar); return $true
    } catch { return $false } finally { $c.Close() }
}
$direct1 = Test-Direct $OfficialHost
Start-Sleep -Milliseconds 300
$direct2 = Test-Direct $OfficialHost
Log "直连 ${OfficialHost}:443 探测：$direct1 / $direct2（两次都要 True 才算稳）" 'info'

if ($PinAnthropicDirect) {
    if (-not ($direct1 -and $direct2)) {
        Log "直连不通，拒绝执行 -PinAnthropicDirect（否则 Claude 直接失联）" 'err'
        $Manual.Add("直连不可用：只能在 YueLink 里给 anthropic 钉固定专线节点")
    } elseif ($DryRun) {
        $Manual.Add("加 -PinAnthropicDirect 执行绕行写入")
    } else {
        $hosts = 'api.anthropic.com;claude.ai;console.anthropic.com;statsig.anthropic.com'
        if ($override -notmatch 'anthropic') {
            Set-ItemProperty -Path $isKey -Name ProxyOverride -Value ("$override;$hosts".Trim(';'))
            Log "已把官方域名写入注册表 ProxyOverride" 'fix'
        }
        $newNo = (($noProxy -split ',') + @('api.anthropic.com','claude.ai','.anthropic.com') | Where-Object { $_ } | Select-Object -Unique) -join ','
        Set-ItemProperty -Path $envKey -Name NO_PROXY -Value $newNo
        Set-ItemProperty -Path $envKey -Name no_proxy -Value $newNo
        Log "已更新 NO_PROXY：$newNo" 'fix'
        $Fixed.Add("官方域名绕开代理（需重启 Claude 生效）")
    }
} elseif ($proxyOn -and $covered) {
    $Manual.Add("代理节点：在 YueLink 里给 anthropic 钉一个固定独享节点，关掉自动选择/负载均衡/故障转移；确认直连可用的话可加 -PinAnthropicDirect 让官方流量彻底绕开机场")
}
Log "说明：按既定红线，脚本不查询任何回显出口 IP 的服务，只做 TCP 可达性判断" 'info'

# ---------------------------------------------------------------- R6 明文密钥
Section 'R6  明文 API Key 暴露面'

$keyRe = 'sk-[A-Za-z0-9_\-]{20,}'
$scanTargets = @($profileCandidates) + @(
    Get-ChildItem -LiteralPath $ClaudeHome -File -Filter '*.txt' -ErrorAction SilentlyContinue | Select-Object -Expand FullName
)
$found = @{}
foreach ($f in ($scanTargets | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)) {
    $i = 0
    foreach ($l in (Get-Content -LiteralPath $f -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        $i++
        foreach ($m in [regex]::Matches($l, $keyRe)) {
            $found["$f|$i"] = $m.Value
        }
    }
}
foreach ($n in $envProps.PSObject.Properties) {
    if ($n.Value -is [string] -and $n.Value -match $keyRe) { $found["HKCU\Environment|$($n.Name)"] = $n.Value }
}
if ($found.Count -eq 0) { Log "未发现明文密钥" 'ok' }
foreach ($k in $found.Keys | Sort-Object) {
    Log "$k  →  $(Mask $found[$k])" 'warn'
}
if ($found.Count -gt 0) {
    $Manual.Add("轮换 $($found.Count) 处明文密钥（脚本不代改第三方 key：改错会直接断服务）")
}

# ---------------------------------------------------------------- 验证
Section '验证：新开的 shell 会拿到什么'

# 先清掉本进程继承下来的 ANTHROPIC_*，再加载 profile —— 否则会把父进程的干净值误判成"没问题"
$probe = @'
Get-ChildItem Env: | Where-Object Name -like 'ANTHROPIC_*' | ForEach-Object { Remove-Item "Env:$($_.Name)" -ErrorAction SilentlyContinue }
$p = $PROFILE.CurrentUserCurrentHost
if (Test-Path $p) { . $p }
"{0}|{1}" -f $env:ANTHROPIC_BASE_URL, $(if ($env:ANTHROPIC_AUTH_TOKEN) { 'TOKEN-SET' } else { 'none' })
'@
foreach ($exe in @('powershell.exe','pwsh.exe')) {
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $out   = & $cmd.Source -NoLogo -NoProfile -Command $probe 2>$null
    $parts = ($out | Select-Object -Last 1) -split '\|'
    $bu    = if ($parts[0]) { $parts[0] } else { '(未设置→官方默认)' }
    $tok   = if ($parts.Count -gt 1) { $parts[1] } else { '?' }
    $lv    = if (($bu -match [regex]::Escape($OfficialHost) -or $bu -like '(*') -and $tok -eq 'none') { 'ok' } else { 'err' }
    Log "$exe 加载 profile 后 → BASE_URL=$bu  AUTH_TOKEN=$tok" $lv
}

# ---------------------------------------------------------------- 周检
if ($InstallWeeklyCheck) {
    Section '安装每周复查计划任务'
    $self = $MyInvocation.MyCommand.Path
    $ps   = (Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source
    if (-not $ps) { $ps = (Get-Command powershell.exe).Source }
    $act  = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -File `"$self`" -DryRun"
    $trg  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 10:00
    Register-ScheduledTask -TaskName 'Claude-BanRisk-Weekly' -Action $act -Trigger $trg -Force | Out-Null
    Log "已注册计划任务 Claude-BanRisk-Weekly（每周日 10:00 只体检不改）" 'fix'
}

# ---------------------------------------------------------------- 汇总
Section '汇总'
if ($Fixed.Count) { Log "已自动修复 $($Fixed.Count) 项：" 'fix'; $Fixed | ForEach-Object { Log "    · $_" 'info' } }
else { Log "本次无需修改" 'ok' }

$ManualUniq = $Manual | Select-Object -Unique
if ($ManualUniq.Count) {
    Log "还需你手动处理 $($ManualUniq.Count) 项：" 'warn'
    $ManualUniq | ForEach-Object { Log "    · $_" 'info' }
}
Log "账号观察期提醒：新账号前 2~4 周别开大规模并行 agent / 定时刷量，别在会话中途切代理节点。" 'info'
Log "完整日志：$LogFile" 'info'

exit ([int]($ManualUniq.Count -gt 0))
