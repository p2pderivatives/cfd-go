Get-ChildItem -File -Filter cfdgo.* | ForEach-Object {((Get-Content $_.FullName -Raw) -replace "`r`n","`n") | Set-Content $_.FullName}
