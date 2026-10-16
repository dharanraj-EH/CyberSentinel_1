param(
    [ValidateSet('System', 'Application', 'Security')][string]$LogName = 'System',
    [ValidateRange(1, 100000)][int]$MaxEvents = 1000,
    [string]$OutputPath = (Join-Path (Get-Location) 'windows_events.xml')
)
$ErrorActionPreference = 'Stop'
# Read-only collection. Security-channel access may require an elevated shell.
$exportPath = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path (Split-Path $exportPath -Parent) -Force | Out-Null
$exportSettings = [Xml.XmlWriterSettings]::new()
$exportSettings.Indent = $true
$exportSettings.Encoding = [Text.UTF8Encoding]::new($false)
$eventWriter = [Xml.XmlWriter]::Create($exportPath, $exportSettings)
$exportCount = 0
try {
    $eventWriter.WriteStartDocument()
    $eventWriter.WriteStartElement('Events')
    Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
        $eventWriter.WriteRaw($_.ToXml())
        $exportCount++
    }
    $eventWriter.WriteEndElement()
    $eventWriter.WriteEndDocument()
} finally {
    $eventWriter.Dispose()
}
Write-Output "Exported $exportCount $LogName events to $exportPath. Import this XML in CyberSentinel Security Monitoring."
