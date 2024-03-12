$file_name = "nxlog-ce-3.2.2329.msi"
$base_url = "https://github.com/UT-CTF/ccdc-scripts/raw/main/windows/"
$base_path = "C:\hash"
$logging_server_ip = "10.10.0.156"

$log_config = @"
<Extension _gelf>
    Module      xm_gelf
</Extension>

# Snare compatible example configuration
# Collecting event log
 <Input in>
     Module      im_msvistalog
 </Input>
 
# Sends Eevent in GELF format to Graylog
 <Output out>
     Module      om_udp
     Host        $logging_server_ip
     Port        12201
     OutputType  GELF
 </Output>
# 
# Connect input 'in' to output 'out'
 <Route 1>
     Path        in => out
 </Route>
"@
$file_url = $base_url + $file_name
$file_path = $base_path + "\" + $file_name

New-Item -Path $base_path -ItemType Directory -Force
Invoke-WebRequest -UseBasicParsing -OutFile $file_path -Uri $file_url
Start-Process msiexec "/i $file_path /qn" -Wait
New-Item -Path "C:\Program Files\nxlog\conf\nxlog.d\hash.conf" -ItemType File -Value $log_config -Force
Restart-Service -Name nxlog
