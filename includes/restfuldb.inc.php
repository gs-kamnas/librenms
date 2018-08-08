<?php
/*
 * LibreNMS RESTfulDB extension.
 *
 * Copyright (c) 2018 Goldman Sachs & Co.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

function restfuldb_config_get($item, $default = null)
{
    global $config;
    if (array_key_exists($item, $config['restfuldb'])) {
        return $config['restfuldb'][$item];
    } else {
        return $default;
    }
}

function restfuldb_update($device, $measurement, $tags, $fields)
{
    global $config, $restfuldb_curl;
    if (!(array_key_exists('restfuldb', $config) && $config['restfuldb']['enable'])) {
        return true;
    }
    // Field separators
    $fs = restfuldb_config_get('field_separator', '.');
    $tag_value_fs = restfuldb_config_get('tag_value_field_separator', '-');

    // Regexes specifying field delimiters, any match is replaced with the corresponding FS
    $measurement_key_regex = restfuldb_config_get('measurement_key_regex', '/[^a-zA-Z0-9]+/');
    $tag_key_regex = restfuldb_config_get('tag_key_regex', '/[^a-zA-Z0-9]+/');
    $tag_value_regex = restfuldb_config_get('tag_value_regex', '/[^a-zA-Z0-9_\-\.\/]+/');

    if (empty($restfuldb)) {
        $restfuldb_curl = curl_init();
        set_curl_proxy($restfuldb_curl);
        curl_setopt($restfuldb_curl, CURLOPT_URL, $config['restfuldb']['url']);
        curl_setopt($restfuldb_curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($restfuldb_curl, CURLOPT_CUSTOMREQUEST, strtoupper($config['restfuldb']['method']));
        curl_setopt($restfuldb_curl, CURLOPT_HTTPHEADER, array("Content-type: application/json"));
        curl_setopt($restfuldb_curl, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($restfuldb_curl, CURLOPT_TIMEOUT, 30); //timeout in seconds
    }
    $timestamp = time();
    $metrics = array();
    $output = array();
    $template = null;
    if (array_key_exists('constants', $config['restfuldb'])
        && is_array($config['restfuldb']['constants'])
    ) {
        $template = $config['restfuldb']['constants'];
    }
    foreach ($tags as $k => $v) {
        $k = trim(preg_replace($tag_key_regex, $fs, $k), $fs);
        /* Workaround for duplicated sensorDescr for Cisco devices */
        $v = preg_replace('/^(.*?) - \1$/', '\1', $v);
        /* user-provided regex substitution */
        $v = trim(preg_replace($tag_value_regex, $fs, $v), $fs);
        if (!empty($v)) {
            $tmp_tags[$k] = $v;
        }
    }

    /* Perform field expansion */
    $multifield = count($fields) > 1;
    foreach ($fields as $k => $v) {
        $mi = "";
        if (array_key_exists('measurementprefix', $config['restfuldb'])) {
            $mi .= $config['restfuldb']['measurementprefix'] . $mi;
        }
        $mi .= $device['type'] . $fs . $device['os'] . $fs;
        if ($multifield) {
            $mi .= strtolower($measurement.$fs.$k);
        } else {
            $mi .= strtolower($measurement);
        }
        if ($v !== null) {
            $metrics[$mi]['name'] = $mi;
            $metrics[$mi]['value'] = (int)$v;
            $metrics[$mi]['timestamp'] = $timestamp;
            $metrics[$mi]['hostname'] = $device['hostname'];
            if ($tmp_tags !== null) {
                $metrics[$mi]['tags'] = $tmp_tags;
            }
        }
    }
    /* Fill the dynamic values into the template, using names from the config mapping */
    foreach ($metrics as $k => $v) {
        /* Copy template if not null */
        $tmp = ($template !== null) ? $template : array();
        /* For each measurement, resolve it in the mapping and insert if specified */
        foreach ($v as $measname => $measval) {
            $mapping = $config['restfuldb']['mapping'];
            if (array_key_exists($measname, $mapping)) {
                $tmp[$mapping[$measname]] = $measval;
            }
        }
        array_push($output, $tmp);
    }
    // post to REST
    $json = json_encode($output);
    curl_setopt($restfuldb_curl, CURLOPT_POSTFIELDS, $json);
    $ret = curl_exec($restfuldb_curl);
    $http_code = curl_getinfo($restfuldb_curl, CURLINFO_HTTP_CODE);
    if ($http_code != 200) {
        log_event("Request to ".$config['restfuldb']['url']." failed with code ".$http_code.": ".$ret, $device['hostname'], 'alert', 5);
        return "HTTP code ".$http_code;
    }
    return true;
}
