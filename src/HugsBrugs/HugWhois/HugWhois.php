<?php

namespace HugsBrugs\HugWhois;

use LayerShifter\TLDExtract\Extract as Extract;

/**
 * @todo integrer proxies pour Curl et fsockopen (possible ?)
 */
class HugWhois
{
    private $domain_or_ip;

    public $is_ip = null;
    public $is_valid_domain = null;
    public $registrable_domain = null;

    private $tld;

    private $full_host = null;
    private $sub_domain = null;
    private $hostname = null;
    private $servers;

    public $whois_text = null;
    public $whois_array = null;

    /**
     * @param string $domain_or_ip full domain name (without trailing dot)
     */
    public function __construct($domain_or_ip)
    {
        $this->domain_or_ip = $domain_or_ip;

        $extract = new Extract();
        $result = $extract->parse($this->domain_or_ip);
        $this->is_ip = $result->isIp();
        $this->sub_domain = $result->subdomain;
        $this->hostname = $result->hostname;
        $this->tld = $result->suffix;
        $this->full_host = $result->getFullHost();
        $this->registrable_domain = $result->getRegistrableDomain();
        $this->is_valid_domain = $result->isValidDomain();
        

        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ), true);

        $this->query_whois();
    }

    /**
     * 
     */
    private function query_whois()
    {
        # check whois for an IP Address
        if($this->is_ip)
        {
            # Linux whois command line
            $output = [];
            exec('whois ' . $this->domain_or_ip, $output);
            $this->whois_text = implode("\n", $output);
        }
        else
        {
            # TDL
            if($this->is_valid_domain)
            {
                $this->info();
            }
            else
            {
                throw new \InvalidArgumentException('Invalid $domain_or_ip syntax');
            }
        }
    }

    /**
     *
     */
    private function info()
    {
        $whois_server = $this->servers[$this->tld][0];

        // If tld have been found
        if ($whois_server != '')
        {
            // if whois server serve replay over HTTP protocol instead of WHOIS protocol
            if (preg_match("/^https?:\/\//i", $whois_server))
            {
                // curl session to get whois reposnse
                $ch = curl_init();
                $url = $whois_server . $this->registrable_domain;

                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

                $data = curl_exec($ch);

                if (curl_error($ch))
                {
                    return "Connection error!";
                }
                else
                {
                    $string = strip_tags($data);
                }
                curl_close($ch);

            }
            else
            {
                // Getting whois information
                $fp = fsockopen($whois_server, 43);
                if (!$fp)
                {
                    return "Connection error!";
                }

                $dom = $this->registrable_domain;
                fputs($fp, "$dom\r\n");

                // Getting string
                $string = '';

                // Checking whois server for .com and .net
                if ($this->tld == 'com' || $this->tld == 'net')
                {
                    while (!feof($fp))
                    {
                        $line = trim(fgets($fp, 128));

                        $string .= $line;

                        $lineArr = explode (":", $line);

                        if (strtolower($lineArr[0]) == 'whois server') {
                            $whois_server = trim($lineArr[1]);
                        }
                    }
                    // Getting whois information
                    $fp = fsockopen($whois_server, 43);
                    if (!$fp)
                    {
                        return "Connection error!";
                    }

                    $dom = $this->registrable_domain;
                    fputs($fp, "$dom\r\n");

                    // Getting string
                    $string = '';

                    while (!feof($fp))
                    {
                        $string .= fgets($fp, 128);
                    }

                // Checking for other tld's
                }
                else
                {
                    while (!feof($fp))
                    {
                        $string .= fgets($fp, 128);
                    }
                }
                fclose($fp);
            }

            $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
            $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

            $this->whois_text = htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);
        }
        else
        {
            throw new \InvalidArgumentException('No whois server for this tld in list!');
        }
    }

    /**
     *
     */
    public function get_whois_text()
    {
        return $this->whois_text;
    }

    /**
     * Hug's method for parsing text
     */
    public function extract_infos($keep_comments = FALSE)
    {
        $Infos = array();
        $comment = 0;
        if($this->whois_text!==null)
        {
            $Infos = explode("\n", $this->whois_text);
            foreach ($Infos as $key => $Info)
            {
                # If line begins with #, remove it
                if(strpos(trim($Info), "#")===0 || strlen(trim($Info))===0)
                {
                    unset($Infos[$key]);
                }
                else
                {
                    $posp = strpos($Info, ":");
                    //echo $posp."<br>";
                    if($posp!==FALSE)
                    {
                        # PROBLEM : WE OVERRIDE key if it exists (e-mail -> admin / tech / owner)
                        $Key1 = substr($Info, 0, $posp);
                        $Val1 = trim(substr($Info, $posp, strlen($Info)-1));
                        $Val1 = trim(str_replace(":", "", $Val1));
                        $Infos[$Key1] = $Val1;
                        unset($Infos[$key]);
                    }
                    else
                    {
                        $infos['comment-' . $comment] = $Info;
                        $comment++; 
                    }
                }
            }
        }
        $this->whois_array = $Infos;
        unset($Infos);
        return $this->whois_array;
    }

    /**
     * @return array $mails All mails found in whois 
     */
    public function get_mails()
    {
        $whois_array = explode("\n", $this->whois_text);

        $mails = [];
        foreach ($whois_array as $key => $value)
        {
            if(strpos($value, "@")!==FALSE)
            {
                $mails[$key] = $value;
            }
        }

        $mails = $this->clean_mail_line($mails);

        return $mails;
    }

    /**
     *
     */
    public function is_available()
    {
        $whois_string = $this->whois_text;

        $not_found_string = '';
        if (isset($this->servers[$this->tld][1]))
        {
           $not_found_string = $this->servers[$this->tld][1];
        }

        $whois_string2 = @preg_replace('/' . $this->domain_or_ip . '/', '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

        $array = explode (":", $not_found_string);
        if ($array[0] == "MAXCHARS")
        {
            if (strlen($whois_string2) <= $array[1])
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            if (preg_match("/" . $not_found_string . "/i", $whois_string))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    /**
     *
     */
    public function extract_whois_registrant_emails($keep_comments = false)
    {
        $infos = [];
        $mails = [];
        $comment = 0;
        if($this->whois_text!==null)
        {
            if(is_array($this->whois_text))
                $this->whois_text = implode("\n", $this->whois_text);

            $infos = explode("\n", $this->whois_text);
            foreach ($infos as $key => $Info)
            {
                # If line begins with #, remove it
                if(strpos(trim($Info), "#")===0 || strpos(trim($Info), "%")===0 || strlen(trim($Info))===0)
                {
                    if($keep_comments===FALSE)
                    {
                        unset($infos[$key]);
                    }
                }
                else
                {
                    $posp = strpos($Info, ":");
                    if($posp!==FALSE)
                    {
                        $Key1 = substr($Info, 0, $posp);
                        $Val1 = trim(substr($Info, $posp, strlen($Info)-1));
                        $Val1 = trim(str_replace(":", "", $Val1));

                        # is it a mail ?
                        if(strpos($Val1, "@")!==FALSE)
                        {
                            # Do not take registrar and abuse emails
                            if(stripos($Key1, 'registrar')===false && stripos($Key1, 'abuse')===false)
                            {
                                $mails[] = $Val1;
                            }
                        }
                        // $infos[$Key1] = $Val1;
                        // unset($infos[$key]);
                    }
                    // else
                    // {
                    //     # is it a mail ?
                    //     if(strpos($Val1, "@")!==FALSE)
                    //     {
                    //         $mails[] = $Val1;
                    //     } 
                    // }
                }
            }
        }

        $mails = $this->clean_mail_line($mails);
        
        return $mails;
    }

    /**
     *
     */
    public function extract_whois_registrar_emails($keep_comments = true)
    {
        $infos = [];
        $mails = [];
        $comment = 0;
        if($this->whois_text!==null)
        {
            if(is_array($this->whois_text))
                $this->whois_text = implode("\n", $this->whois_text);

            $infos = explode("\n", $this->whois_text);

            foreach ($infos as $key => $Info)
            {
                //echo $Info . '<br>';
                # If line begins with #, remove it
                if(strpos(trim($Info), "#")===0 || strpos(trim($Info), "%")===0 || strlen(trim($Info))===0)
                {
                    if($keep_comments===false)
                    {
                        unset($infos[$key]);
                    }
                }

                $posp = strpos($Info, ":");
                if($posp!==FALSE)
                {
                    $Key1 = substr($Info, 0, $posp);
                    $Val1 = trim(substr($Info, $posp, strlen($Info)-1));
                    $Val1 = trim(str_replace(":", "", $Val1));

                    # is it a mail ?
                    if(strpos($Val1, "@")!==FALSE)
                    {
                        $mails[] = $Val1;
                    }
                }
                else
                {
                    # is it a mail ?
                    if(strpos($Info, "@")!==FALSE)
                    {
                        $mails[] = $Info;
                    }
                }
            }
        }

        $mails = $this->clean_mail_line($mails);

        return $mails;
    }

    /**
     * removes extra sheet
     */
    private function clean_mail_line($mails)
    {
        # clean mail when not alone chars
        foreach ($mails as $key => $mail)
        {
            if(substr_count($mail, " ") > 0)
            {
                $mails_tmp = explode(" ", $mail);
                foreach ($mails_tmp as $mail_tmp)
                {
                    if(stripos($mail_tmp, "@")>0)
                    {
                        $mails[$key] = $mail_tmp;
                        # break at first
                        break;
                    }
                }
            }
        }
        
        # last clean ''
        foreach ($mails as $key => $mail)
        {
            $mails[$key] = str_replace("'", "", $mail);
        }

        # return unique values
        $mails = array_unique($mails);

        return $mails;
    }

    /**
     * @return string registrable_domain
     */
    public function get_registrable_domain()
    {
        return $this->registrable_domain;
    }

    /**
     *
     */
    public function whois_html()
    {
        return nl2br($this->whois_text);
    }

    /**
     * @return string full domain name
     */
    public function get_domain()
    {
        return $this->domain_or_ip;
    }

    /**
     * @return string hostname
     */
    public function get_hostname()
    {
        return $this->hostname;
    }

    /**
     * @return string full_host
     */
    public function get_full_host()
    {
        return $this->full_host;
    }
    
    /**
     * @return string top level domains separated by dot
     */
    public function get_tld()
    {
        return $this->tld;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function get_sub_domain()
    {
        return $this->sub_domain;
    }

    /**
     * @return bool is_ip 
     */
    public function is_ip()
    {
        return $this->is_ip;
    }
}
