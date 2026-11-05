//go:build windows

package seccollect

import (
	"context"
	"errors"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// hwScript asks Windows what the machine is made of, once, and prints it as JSON. Serial numbers and MAC addresses are
// not asked for. Every query is allowed to fail on its own: a machine without a video controller still has a processor.
const hwScript = `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference = 'SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor)
$arr = Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1
$dimm = @(Get-CimInstance Win32_PhysicalMemory)
$gpu = @(Get-CimInstance Win32_VideoController)
$pd = @(Get-PhysicalDisk)
$nic = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.Virtual })
$ips = @(Get-NetIPAddress | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '::1' -and $_.IPAddress -notlike 'fe80*' })
$gw = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' })
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4)
$d = $null
if ($bios.ReleaseDate) { $d = $bios.ReleaseDate.ToString('dd.MM.yyyy') }
ConvertTo-Json -Depth 5 -Compress ([pscustomobject]@{
  vendor = $cs.Manufacturer
  model = $cs.Model
  bios = (('{0} {1}' -f $bios.SMBIOSBIOSVersion, $d).Trim())
  build = (('{0} {1}' -f $os.Caption, $os.BuildNumber).Trim())
  cpu = [pscustomobject]@{
    name = ($cpu | Select-Object -First 1).Name
    cores = [int](($cpu | Measure-Object NumberOfCores -Sum).Sum)
    threads = [int](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
    mhz = [int]($cpu | Select-Object -First 1).MaxClockSpeed
    cache_kb = [int]($cpu | Select-Object -First 1).L3CacheSize
  }
  mem = [pscustomobject]@{
    slots = [int]$arr.MemoryDevices
    used = [int]$dimm.Count
    type = [int]($dimm | Select-Object -First 1).SMBIOSMemoryType
    speed = [int]($dimm | Select-Object -First 1).ConfiguredClockSpeed
  }
  disks = @($pd | ForEach-Object { [pscustomobject]@{ name = $_.FriendlyName; size = [int64]$_.Size; media = [string]$_.MediaType; bus = [string]$_.BusType } })
  gpus = @($gpu | ForEach-Object { [pscustomobject]@{ name = $_.Name; mem = [int64]$_.AdapterRAM; driver = $_.DriverVersion } })
  nics = @($nic | ForEach-Object { $n = $_; [pscustomobject]@{ name = $n.Name; speed = [int64]$n.Speed; ips = @($ips | Where-Object { $_.InterfaceAlias -eq $n.Name } | ForEach-Object { $_.IPAddress }); gateway = [string](($gw | Where-Object { $_.InterfaceAlias -eq $n.Name } | Sort-Object RouteMetric | Select-Object -First 1).NextHop); dns = @($dns | Where-Object { $_.InterfaceAlias -eq $n.Name } | ForEach-Object { $_.ServerAddresses }) } })
})`

func readHardware(ctx context.Context, r Runner) (secproto.Hardware, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res := r.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", hwScript)
	if res.Err != nil || res.ExitCode != 0 {
		return secproto.Hardware{}, errors.New("seccollect: the hardware query failed")
	}
	return ParseWinHardware(res.Stdout)
}
