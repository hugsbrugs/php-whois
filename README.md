# php-whois

https://github.com/phpWhois/phpWhois
https://github.com/regru/php-whois

http://superuser.com/questions/758647/how-to-whois-new-tlds

http://www.phpwhois.org/
http://localhost/vendor/phpwhois/phpwhois/example.php?query=free.fr&output=object


Mettre le fichier whois.conf dans :
/etc/whois.conf
Pour forcer la recherche en ligne de commande

```
$domain_or_ip = 'sport24.lefogaro.fr'; // '212.95.72.8'

# Create Whois object
$HugWhois = new HugWhois($domain_or_ip);

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
```
