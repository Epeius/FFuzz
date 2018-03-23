REM run this script when bundling the VM or in the bootstra.bat script, before loading the driver
REM need to "Run as admin"
REM for testing, can run certmgrt to verify that the CA certificate has been installed
REM do not forget to copy CyberHaven_CA.cer

certutil -addstore Root CyberHaven_CA.cer
