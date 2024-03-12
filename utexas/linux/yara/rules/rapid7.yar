rule Mettle {
  meta:
    uuid        = "94549b1c-5d3e-4b6d-a131-dbe2cfd8e51a"
    version     = "1.0"
    date        = "2024-03-02"
    modified    = "2024-03-02"
    status      = "RELEASED"
    sharing     = "TLP:CLEAR"
    source      = "PERSONAL"
    author      = "mail@aadhithya.cloud"
    description = "detect mettle payloads"
    actor       = "Rapid7"
    category    = "MALWARE"
    technique   = "BACKDOOR"
    hash        = "89f6e19b066027239b5dec96ce69fb970388c388"

  strings:
    $str0  = "mettle -U"
    $str1  = "mettle_signal_handler"
    $str2  = "mettle_get_machine_id"
    $str3  = "mettle_get_fqdn"
    $str4  = "mettle_get_tlv_dispatcher"
    $str5  = "mettle_free"
    $str6  = "mettle_get_procmgr"
    $str7  = "mettle_set_uuid_base64"
    $str8  = "mettle_get_channelmgr"
    $str9  = "mettle_get_extmgr"
    $str10 = "mettle_set_session_guid_base64"
    $str11 = "mettle_get_sigar"
    $str12 = "mettle_start"
    $str13 = "mettle_get_modulemgr"
    $str14 = "mettle_console_start_interactive"
    $str15 = "mettle_get_c2"
    $str16 = "mettle_get_loop"

  condition:
    any of them
}
