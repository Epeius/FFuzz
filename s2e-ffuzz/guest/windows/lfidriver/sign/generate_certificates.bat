REM run from the MS Visual Studio Developer console
REM press "None" to have no password for the certificates

makecert -r -pe -n "CN=CyberHaven_CA" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv CyberHaven_CA.pvk CyberHaven_CA.cer

makecert -pe -n "CN=CyberHaven_SPC" -a sha256 -cy end -sky signature -ic CyberHaven_CA.cer -iv CyberHaven_CA.pvk -sv CyberHaven_SPC.pvk CyberHaven_SPC.cer

pvk2pfx -pvk CyberHaven_SPC.pvk -spc CyberHaven_SPC.cer -pfx CyberHaven_SPC.pfx



