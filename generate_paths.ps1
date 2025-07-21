#Requires -Version 5.1
<#
.SYNOPSIS
    Calculates relative paths for files/folders dropped onto the script and copies them to the clipboard.
#>

param (
    # This will automatically receive all dropped files and folders.
    [string[]]$Paths
)

# --- Anti-double-click check --- 
if ($Paths.Count -eq 0) {
    Write-Host "`n!!!!!!!!!!!!!!!!!!!!!!!!!!  错误  !!!!!!!!!!!!!!!!!!!!!!!!!!`n" -ForegroundColor Red
    Write-Host "   请不要双击运行本文件。`n" -ForegroundColor Yellow
    Write-Host "   正确用法:`n   请将一个或多个文件或文件夹，拖拽到 (生成附件路径.bat) 的图标上。`n" -ForegroundColor Yellow
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`n" -ForegroundColor Red
    Read-Host "按任意键退出..."
    exit
}

# --- Main Logic --- 
try {
    # Get the directory where this script is located.
    $scriptDir = $PSScriptRoot
    
    # Define the absolute path to the attachments repository.
    $repoPath = Join-Path -Path $scriptDir -ChildPath "attachments_repository"

    $relativePaths = @()

    foreach ($singlePath in $Paths) {
        # Resolve the full, absolute path of the dropped item.
        $fullPath = (Resolve-Path -LiteralPath $singlePath).ProviderPath

        # Core Logic: Calculate the relative path by removing the repository base path.
        if ($fullPath.StartsWith($repoPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relativePath = $fullPath.Substring($repoPath.Length).TrimStart('\')
            $relativePaths += $relativePath
        } else {
            Write-Warning "文件或文件夹 '$fullPath' 不在 '$repoPath' 目录中，已跳过。"
        }
    }

    if ($relativePaths.Count -gt 0) {
        # Join all calculated relative paths with a semicolon.
        $resultString = $relativePaths -join ';'

        # Copy the final string to the clipboard.
        Set-Clipboard -Value $resultString

        # --- Display the result clearly to the user ---
        Write-Host "`n============================================================================" -ForegroundColor Green
        Write-Host " 以下路径已成功生成，并已自动复制到您的剪贴板:" -ForegroundColor Green
        Write-Host "============================================================================`n" -ForegroundColor Green
        Write-Host $resultString -ForegroundColor White
        Write-Host "`n============================================================================`n" -ForegroundColor Green
        Write-Host " 现在您可以直接到 Excel 或数据文件中粘贴 (Ctrl + V) 了。`n" -ForegroundColor Cyan
    } else {
        Write-Warning "没有找到任何有效的文件或文件夹来生成路径。"
    }
} catch {
    Write-Error "在处理过程中发生意外错误:"
    Write-Error $_.Exception.Message
}

Read-Host "按任意键退出..."
