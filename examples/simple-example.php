<!DOCTYPE html>
<html>
<head>
    <title>Test Whois</title>
    <meta charset="UTF-8">
</head>
<body>

<?php

ini_set('display_errors', 1);
ini_set('error_reporting', E_ALL);
ini_set('max_execution_time', 0); 

// Load composer
require_once __DIR__ . '/../vendor/autoload.php';

use HugsBrugs\HugWhois\HugWhois as HugWhois;


$tlds = [
    'xn--rachat-de-crdits-mqb.net', // test IDN domain names
    'sport24.lefigaro.fr', // test subdomain
    'cacouyousupertramp.fr', // unavailable
    '212.95.72.8', // IP of sport24.lefigaro.fr
];

foreach ($tlds as $tld)
{
	# Create Whois object
    $HugWhois = new HugWhois($tld);
    
    $whois = [];

    # Query whois database and return whois text as UTF-8
    $whois['text'] = $HugWhois->get_whois_text();

    $whois['is_ip'] = $HugWhois->is_ip();

    # Is this tld available ?
    $whois['is_available'] = $HugWhois->is_available();

    # Extract whois informations
    $whois['infos'] = $HugWhois->extract_infos();
    
    # Extract all mails from whois
    $whois['mails'] = $HugWhois->get_mails();

    $whois['registrant_emails'] = $HugWhois->extract_whois_registrant_emails();
    $whois['registrar_emails'] = $HugWhois->extract_whois_registrar_emails();
    
    # Return whois as HTML (\n replaced by <br>)
    //$whois['html'] = $HugWhois->whois_html();
    
    # helper functions
    $whois['registrable_domain'] = $HugWhois->get_registrable_domain();
    $whois['domain'] = $HugWhois->get_domain();
    $whois['hostname'] = $HugWhois->get_hostname();
    $whois['full_host'] = $HugWhois->get_full_host();
    $whois['tlds'] = $HugWhois->get_tld();
    $whois['subdomain'] = $HugWhois->get_sub_domain();

    # Print
    echo $tld . ' : <br>';
    echo '<pre>';print_r($whois);echo '</pre><br>';

    sleep(3);
}



?>

</body>
</html>
