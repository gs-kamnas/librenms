source: Extensions/metrics/RESTfulDB.md
# Enabling support for generic time series datastores implementing a RESTful API.

All this interface provides is a generic and somewhat flexible interface that submits metrics retrieved from devices
to a generic RESTful API in JSON format. Due to the fact that this is made to be as "universal" as possible,
you are responsible for ensuring that the output format defined is suitable for whatever backend you are interfacing
to.

### Requirements
 - RESTful web API capable of accepting data represented as JSON objects

The setup of your particular web API is completely out of scope and therefore unsupported.

RRD will continue to function as normal when this is enabled,
therefore this should not affect and does not replace such functionality of LibreNMS.

### Config
All parameters are *shown equal to thier default values*

# Enables this functionality
$config['restfuldb']['enable'] = false;

# String to be used as the field separator in measurement and tag keys
$config['restfuldb']['field_separator'] = '.';

# String to be used as a field separator in tag values
$config['restfuldb']['tag_value_field_separator'] = '-';

# Regex that defines what characters in the measurement name are to be replaced with the field separator.
$config['restfuldb'['measurement_key_regex'] = '/[^a-zA-Z0-9]+/';

# Same as above but applied to tag keys
$config['restfuldb'['tag_key_regex'] = '/[^a-zA-Z0-9]+/';

# Regex that defines what characters in the tag value are to be replaced with the `tag_value_field_separator`.
$config['restfuldb'['tag_value_regex'] = '/[^a-zA-Z0-9_\-\.\/]+/';

# Prefix appended to all measurement keys
$config['restfuldb']['measurementprefix'] = '';

# URL to which metrics should be submitted.
$config['restfuldb']['url'] = 'http://example.com/api/metrics';

# HTTP method to be used when submitting data, POST and PUT are supported.
$config['restfuldb']['method'] = 'POST';

# Mapping between LibreNMS' internal metric names and the JSON keys submitted to the API
$config['restfuldb']['mapping'] = array('hostname' => 'myCustomHostname',
                                        'name' => 'mySystemName',
                                        'value' => 'mySpecialValue',
                                        'tags' => 'myTagArray',
                                        'timestamp' => 'myTimeStamp');

# Definition of any constant fields that should be submitted to the API
$config['restfuldb']['constants'] = array('group' => 'myConstantGroup');
```
