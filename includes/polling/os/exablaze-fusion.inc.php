<?php

$snmp_data = snmp_get_multi_oid("fusionInfoBoard fusionInfoSerial fusionInfoVersion fusionInfoSoftware", "-OQUs", "EXALINK-FUSION-MIB");

$hardware = $snmp_data['fusionInfoBoard'];
$serial = $snmp_data['fusionInfoSerial'];
$version = $snmp_data['fusionInfoVersion'] . " " . $snmp_data['fusionInfoSoftware'];
