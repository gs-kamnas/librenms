<?php

$snmp_data = snmp_get_multi_oid($device, "fusionInfoBoard fusionInfoSerial fusionInfoVersion fusionInfoSoftware", "-OQs", "EXALINK-FUSION-MIB");

$hardware = $snmp_data['fusionInfoBoard'];
$serial = $snmp_data['fusionInfoSerial'];
$version = $snmp_data['fusionInfoVersion'] . " " . $snmp_data['fusionInfoSoftware'];
