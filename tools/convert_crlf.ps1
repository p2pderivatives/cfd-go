Get-ChildItem -File -Filter cfdgo.* | ForEach-Object {((Get-Content $_.FullName -Raw) -replace "`r","") | Set-Content $_.FullName -NoNewline}
