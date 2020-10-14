mc.exe -v radiator-eventlog.mc
rc -r radiator-eventlog.rc
link.exe -dll -noentry -out:radiator-eventlog.dll radiator-eventlog.res
