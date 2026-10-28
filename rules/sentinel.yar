rule EICAR_Test_File
{
    meta:
        confidence = "alta"
        description = "Archivo de prueba EICAR (antivirus test)"
        mitre = "T1204.002"
        severity = "alto"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Download_And_Execute
{
    meta:
        confidence = "media"
        description = "Descarga y ejecución de payload remoto"
        mitre = "T1105"
        severity = "alto"
    strings:
        $dl1 = "DownloadFile" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "URLDownloadToFile" nocase
        $dl4 = "urlretrieve" nocase
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "IEX(" nocase
        $exec3 = "os.system" nocase
        $exec4 = "subprocess" nocase
    condition:
        any of ($dl*) and any of ($exec*)
}

rule Base64_Obfuscation
{
    meta:
        confidence = "media"
        description = "Payload codificado en base64 largo"
        mitre = "T1140"
        severity = "medio"
    strings:
        $b1 = "base64.b64decode"
        $b2 = "FromBase64String" nocase
        $b3 = "atob(" nocase
        $encoded = /[A-Za-z0-9+\/]{80,}={0,2}/
    condition:
        any of ($b*) and $encoded
}

rule PowerShell_Encoded_Command
{
    meta:
        confidence = "alta"
        description = "Comando powershell con flag encoded (-enc/-EncodedCommand)"
        mitre = "T1059.001"
        severity = "alto"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc " nocase
        $enc2 = "-encodedcommand" nocase
        $hidden = "-w hidden" nocase
        $bypass = "bypass" nocase
    condition:
        $ps and (any of ($enc*) or ($hidden and $bypass))
}

rule Process_Injection_API
{
    meta:
        confidence = "alta"
        description = "Imports típicos de inyección de proceso"
        mitre = "T1055"
        severity = "crítico"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "QueueUserAPC"
        $a5 = "SetThreadContext"
    condition:
        2 of them and not uint16(0) == 0x5A4D
}

rule Ransomware_Shadow_Copy
{
    meta:
        confidence = "alta"
        description = "Comandos de borrado de copias de seguridad (ransomware)"
        mitre = "T1490"
        severity = "crítico"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wbadmin delete catalog" nocase
        $s3 = "bcdedit /set" nocase
        $s4 = "cipher /w" nocase
    condition:
        any of them
}

rule Suspicious_Startup_Persistence
{
    meta:
        confidence = "baja"
        description = "Escritura en rutas de auto-arranque"
        mitre = "T1547.001"
        severity = "alto"
    strings:
        $reg1 = "CurrentVersion\\Run" nocase
        $reg2 = "CurrentVersion\\RunOnce" nocase
        $reg3 = "Startup\\" nocase
        $reg4 = "schtasks /create" nocase
    condition:
        any of them
}

rule Nested_Archive_Executable
{
    meta:
        confidence = "baja"
        description = "Ejecutable embebido dentro de archivo (MZ en contenedor)"
        mitre = "T1027.009"
        severity = "alto"
    strings:
        $mz = { 4D 5A }
        $pk = { 50 4B 03 04 }
    condition:
        $pk at 0 and $mz in (2000..filesize)
}
