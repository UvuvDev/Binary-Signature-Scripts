rule PyInstallerMagic
{
    meta:
        description = "https://www.pyinstaller.org/"
    strings:
        $magic = { 4D 45 49 0C 0B 0A 0B 0E }

    condition:
        $magic
}

rule PyInstallerStrings
{
    meta:
	description = "https://www.pyinstaller.org/"
    strings:
        $s1 = "PyInstaller" ascii wide nocase
        $s2 = "_MEIPASS" ascii wide
        $s3 = "pyi-" ascii wide
        $s4 = "PYZ-00.pyz" ascii wide

    condition:
        2 of them
}
