-- A first set of commands for Windows machines (PowerShell, which is what the terminal opens there).
INSERT INTO command_templates (os, name, command, note, danger) VALUES
 ('windows', 'Диски', $$Get-PSDrive -PSProvider FileSystem | Select-Object Name,@{n='UsedGB';e={[math]::Round($_.Used/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}} | Format-Table -AutoSize$$, 'Занято и свободно по дискам', false),
 ('windows', 'Память', $$Get-CimInstance Win32_OperatingSystem | Select-Object @{n='FreeGB';e={[math]::Round($_.FreePhysicalMemory/1MB,1)}},@{n='TotalGB';e={[math]::Round($_.TotalVisibleMemorySize/1MB,1)}}$$, 'Свободная и вся память', false),
 ('windows', 'Кто ест память', $$Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name,Id,@{n='MB';e={[math]::Round($_.WS/1MB)}} | Format-Table -AutoSize$$, '', false),
 ('windows', 'Кто грузит процессор', $$Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,@{n='CPUsec';e={[math]::Round($_.CPU)}} | Format-Table -AutoSize$$, 'Больше всего процессорного времени с запуска', false),
 ('windows', 'Службы, которые должны работать', $$Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select-Object Name,Status,DisplayName | Format-Table -AutoSize$$, 'Автозапуск включён, а служба стоит', false),
 ('windows', 'Ошибки системного журнала за час', $$Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddHours(-1)} -MaxEvents 30 -ErrorAction SilentlyContinue | Select-Object TimeCreated,ProviderName,Id,Message | Format-List$$, '', false),
 ('windows', 'Кто слушает порты', $$Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | Format-Table -AutoSize$$, '', false),
 ('windows', 'Кто сидит на машине', 'query user', 'Сеансы пользователей, в том числе по RDP', false),
 ('windows', 'Сколько работает', $$(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime$$, 'Время с последней перезагрузки', false),
 ('windows', 'Перезагрузка', 'Restart-Computer -Force', 'Машина уйдёт на перезагрузку сразу, без предупреждения', true);
