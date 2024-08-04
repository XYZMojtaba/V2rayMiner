<?php

// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

function getTelegramChannelConfigs($username)
{
    $sourceArray = explode(",", $username);
    $configsList = [];
    
    foreach ($sourceArray as $source) {
        $html = file_get_contents("https://t.me/s/" . $source);
        
        $types = ["vmess", "vless", "trojan", "ss", "tuic", "hysteria", "hysteria2", "hy2"];
        $configs = [];
        
        foreach ($types as $type) {
            $configs[$type] = getConfigItems($type, $html);
        }
        
        foreach ($configs as $type => $configsArray) {
            foreach ($configsArray as $config) {
                if (is_valid($config)) {
                    $fixedConfig = str_replace("amp;", "", removeAngleBrackets($config));
                    $correctedConfig = correctConfig("{$fixedConfig}", $type);
                    $configsList[] = $correctedConfig;
                }
            }
        }
    }
    
    // Limit to 100 configs
    return array_slice($configsList, 0, 100);
}

function configParse($input, $configType)
{
    if ($configType === "vmess") {
        $vmess_data = substr($input, 8);
        $decoded_data = json_decode(base64_decode($vmess_data), true);
        return $decoded_data;
    } elseif (in_array($configType, ["vless", "trojan", "tuic", "hysteria", "hysteria2", "hy2"])) {
        $parsedUrl = parse_url($input);
        $params = [];
        if (isset($parsedUrl["query"])) {
            parse_str($parsedUrl["query"], $params);
        }
        $output = [
            "protocol" => $configType,
            "username" => isset($parsedUrl["user"]) ? $parsedUrl["user"] : "",
            "hostname" => isset($parsedUrl["host"]) ? $parsedUrl["host"] : "",
            "port" => isset($parsedUrl["port"]) ? $parsedUrl["port"] : "",
            "params" => $params,
            "hash" => isset($parsedUrl["fragment"]) ? $parsedUrl["fragment"] : "TVC" . getRandomName(),
        ];

        if ($configType === "tuic") {
            $output["pass"] = isset($parsedUrl["pass"]) ? $parsedUrl["pass"] : "";
        }
        return $output;
    } elseif ($configType === "ss") {
        $url = parse_url($input);
        if (isBase64($url["user"])) {
            $url["user"] = base64_decode($url["user"]);
        }
        list($encryption_method, $password) = explode(":", $url["user"]);
        $server_address = $url["host"];
        $server_port = $url["port"];
        $name = isset($url["fragment"]) ? urldecode($url["fragment"]) : "TVC" . getRandomName();
        $server = [
            "encryption_method" => $encryption_method,
            "password" => $password,
            "server_address" => $server_address,
            "server_port" => $server_port,
            "name" => $name,
        ];
        return $server;
    }
}

function reparseConfig($configArray, $configType)
{
    if ($configType === "vmess") {
        $encoded_data = base64_encode(json_encode($configArray));
        $vmess_config = "vmess://" . $encoded_data;
        return $vmess_config;
    } elseif (in_array($configType, ["vless", "trojan", "tuic", "hysteria", "hysteria2", "hy2"])) {
        $url = $configType . "://";
        $url .= addUsernameAndPassword($configArray);
        $url .= $configArray["hostname"];
        $url .= addPort($configArray);
        $url .= addParams($configArray);
        $url .= addHash($configArray);
        return $url;
    } elseif ($configType === "ss") {
        $user = base64_encode($configArray["encryption_method"] . ":" . $configArray["password"]);
        $url = "ss://$user@{$configArray["server_address"]}:{$configArray["server_port"]}";
        if (!empty($configArray["name"])) {
            $url .= "#" . str_replace(" ", "%20", $configArray["name"]);
        }
        return $url;
    }
}

function addUsernameAndPassword($obj)
{
    $url = "";
    if ($obj["username"] !== "") {
        $url .= $obj["username"];
        if (isset($obj["pass"]) && $obj["pass"] !== "") {
            $url .= ":" . $obj["pass"];
        }
        $url .= "@";
    }
    return $url;
}

function addPort($obj)
{
    $url = "";
    if (isset($obj["port"]) && $obj["port"] !== "") {
        $url .= ":" . $obj["port"];
    }
    return $url;
}

function addParams($obj)
{
    $url = "";
    if (!empty($obj["params"])) {
        $url .= "?" . http_build_query($obj["params"]);
    }
    return $url;
}

function addHash($obj)
{
    $url = "";
    if (isset($obj["hash"]) && $obj["hash"] !== "") {
        $url .= "#" . str_replace(" ", "%20", $obj["hash"]);
    }
    return $url;
}

function isBase64($input)
{
    if (base64_encode(base64_decode($input)) === $input) {
        return true;
    }
    return false;
}

function getRandomName()
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $name = '';
    for ($i = 0; $i < 10; $i++) {
        // Get a random letter from the alphabet
        $randomLetter = $alphabet[rand(0, strlen($alphabet) - 1)];
        // Add the letter to the name string
        $name .= $randomLetter;
    }
    return $name;
}

function correctConfig($config, $type)
{
    $configsHashName = [
        "vmess" => "ps",
        "vless" => "hash",
        "trojan" => "hash",
        "tuic" => "hash",
        "hysteria" => "hash",
        "hysteria2" => "hash",
        "hy2" => "hash",
        "ss" => "name",
    ];
    $configHashName = $configsHashName[$type];

    $parsedConfig = configParse($config, $type);
    $configHashTag = generateName($parsedConfig, $type);
    $parsedConfig[$configHashName] = $configHashTag;

    $rebuildedConfig = reparseConfig($parsedConfig, $type);
    return $rebuildedConfig;
}

function is_ip($string)
{
    $ip_pattern = '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/';
    if (preg_match($ip_pattern, $string)) {
        return true;
    } else {
        return false;
    }
}

function convertToJson($input)
{
    // Split the input string by newline
    $lines = explode("\n", $input);

    // Initialize an empty array to store the key-value pairs
    $data = [];

    // Loop through each line
    foreach ($lines as $line) {
        // Split the line by the equals sign
        $parts = explode("=", $line);

        // If the line has an equals sign and is not empty
        if (count($parts) == 2 && !empty($parts[0]) && !empty($parts[1])) {
            // Trim any whitespace from the key and value
            $key = trim($parts[0]);
            $value = trim($parts[1]);

            // Add the key-value pair to the data array
            $data[$key] = $value;
        }
    }

    // Convert the data array to a JSON string
    $json = json_encode($data);

    return $json;
}

function ip_info($ip)
{
    if (is_ip($ip) === false) {
        $ip_address_array = dns_get_record($ip, DNS_A);
        if (empty($ip_address_array)) {
            return null;
        }
        $randomKey = array_rand($ip_address_array);
        $ip = $ip_address_array[$randomKey]["ip"];
    }

    // List of API endpoints
    $endpoints = [
        "https://ipapi.co/{ip}/json/",
        "https://ipwhois.app/json/{ip}",
        "http://www.geoplugin.net/json.gp?ip={ip}",
        "https://api.ipbase.com/v1/json/{ip}",
    ];

    // Iterate through each endpoint until a successful response is received
    foreach ($endpoints as $endpoint) {
        $url = str_replace("{ip}", $ip, $endpoint);
        $json = file_get_contents($url);
        if ($json !== false) {
            $data = json_decode($json, true);
            // Ensure the response contains latitude and longitude data
            if (isset($data["latitude"]) && isset($data["longitude"])) {
                return [
                    "latitude" => $data["latitude"],
                    "longitude" => $data["longitude"],
                ];
            }
        }
    }

    return null; // No valid response from any endpoint
}


function generateName($configArray, $configType)
{
    $host = $configArray["hostname"];
    $coordinates = ip_info($host);

    if (isset($coordinates["latitude"]) && isset($coordinates["longitude"])) {
        $latitude = $coordinates["latitude"];
        $longitude = $coordinates["longitude"];
        $apiKey = 'API_KEY'; // Replace with your actual API key
        $url = "https://maps.googleapis.com/maps/api/geocode/json?latlng={$latitude},{$longitude}&key={$apiKey}";

        $response = file_get_contents($url);
        $data = json_decode($response, true);

        if (!empty($data['results'])) {
            $locationName = $data['results'][0]['formatted_address'];
            $location = str_replace(" ", "_", $locationName);
            return $location;
        }
    }
    return "TVC" . getRandomName();
}

function getConfigItems($configType, $html)
{
    preg_match_all(
        "/(ss:\/\/|vmess:\/\/|vless:\/\/|trojan:\/\/|tuic:\/\/|hysteria:\/\/|hysteria2:\/\/|hy2:\/\/)([^<>\s]+)/i",
        $html,
        $matches
    );
    return array_filter($matches[0], function ($match) use ($configType) {
        return strpos($match, "{$configType}://") === 0;
    });
}

function is_valid($input)
{
    if (strlen($input) <= 50) {
        return false;
    }
    return true;
}

function removeAngleBrackets($input)
{
    $input = str_replace("<", "", $input);
    $input = str_replace(">", "", $input);
    return $input;
}

header('Content-Type: application/json');

$input = filter_input(INPUT_POST, 'input', FILTER_SANITIZE_STRING);
$configsList = getTelegramChannelConfigs($input);
echo json_encode($configsList);
?>
