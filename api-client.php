<?php
/*
mofh-vp-api-wrapper API
Sucessor to VPClient.
*/
error_reporting(E_ERROR | E_PARSE);

/* Backwards compatibility for PHP 8 functions */
if(!function_exists('str_contains')) {
    function str_contains($haystack, $needle)
    {
        return '' === $needle || strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle)
    {
        $needle_len = strlen($needle);
        return $needle_len === 0 || 0 === substr_compare($haystack, $needle, - $needle_len);
    }
}

class Wrapper
{
    private $cpanel_url = "https://cpanel.byethost.com";
    private $logged_in = false;
    private $vistapanel_session = "";
    private $vistapanel_session_name = "PHPSESSID";
    private $account_username = "";
    private $cookie = "";

    // --------------- Private Helper Methods ---------------

    private function get_line_with_string($content, $str)
    {
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            if (str_contains($line, $str)) {
                return $line;
            }
        }
        return -1;
    }

    private function simple_curl(
        $url = "",
        $post = false,
        $postfields = [],
        $header = false,
        $httpheader = [],
        $followlocation = false
    )
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if ($post) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postfields);
        }
        if ($header) {
            curl_setopt($ch, CURLOPT_HEADER, true);
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $httpheader);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt(
            $ch,
            CURLOPT_USERAGENT,
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13"
        );
        if ($followlocation) {
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        }
        $result = curl_exec($ch);
        $result_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        //Check for errors
        if (str_contains($result_url, $this->cpanel_url . "/panel/indexpl.php?option=error")) {
            $dom = new DOMDocument();
            libxml_use_internal_errors(true);
            $dom->loadHTML($result);
            $xpath = new DOMXPath($dom);

            $alert_message_nodes = $xpath->query('//div[contains(@class, "alert-message")]');
            if ($alert_message_nodes->length > 0) {
                $error_message = trim($alert_message_nodes[0]->textContent);
                throw new Exception($error_message);
            }
        }

        return $result;
    }

    private function check_cpanel_url()
    {
        if (empty($this->cpanel_url)) {
            throw new Exception("Please set cpanel_url first.");
        }
        if (substr($this->cpanel_url, -1) == "/") {
            $this->cpanel_url = substr_replace($this->cpanel_url, "", -1);
        }
        return true;
    }

    private function check_login()
    {
        $this->check_cpanel_url();
        if (!$this->logged_in) {
            throw new Exception("Not logged in.");
        }
        return true;
    }

    private function check_for_empty_params($params)
    {
        foreach ($params as $index => $parameter) {
            if (empty($parameter)) {
                throw new Exception($index . " is required.");
            }
        }
    }

    private function get_token()
    {
        $this->check_login();
        $homepage = $this->simple_curl($this->cpanel_url . "/panel/indexpl.php", false, [], false, [$this->cookie]);
        $json = $this->get_line_with_string($homepage,"/panel\/indexpl.php?option=domains&ttt=");
        $json = substr_replace($json, "", -1);
        $json = json_decode($json, true);
        $url = $json["url"];
        return (int) filter_var($url, FILTER_SANITIZE_NUMBER_INT);
    }

    private function get_table_elements($url = "", $id = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("url"));
        $html = $this->simple_curl($url, false, [], false, [$this->cookie]);
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        if (empty($id)) {
            $header = $dom->getElementsByTagName("th");
            $detail = $dom->getElementsByTagName("td");
        } else {
            $header = $dom->getElementById($id)->getElementsByTagName("th");
            $detail = $dom->getElementById($id)->getElementsByTagName("td");
        }
        $a_data_table_header_html = [];
        foreach ($header as $node_header) {
            $a_data_table_header_html[] = trim($node_header->textContent);
        }
        $i = 0;
        $j = 0;
        foreach ($detail as $s_node_detail) {
            $a_data_table_detail_html[$j][] = trim($s_node_detail->textContent);
            $i = $i + 1;
            $j = $i % count($a_data_table_header_html) == 0 ? $j + 1 : $j;
        }
        for ($i = 0; $i < count($a_data_table_detail_html); $i++) {
            for ($j = 0; $j < count($a_data_table_header_html); $j++) {
                $a_temp_data[$i][$a_data_table_header_html[$j]] =
                    $a_data_table_detail_html[$i][$j];
            }
        }
        return $a_temp_data;
    }

    private function table_to_array($html)
    {
        $doc = new DOMDocument();
        $doc->loadHTML($html);
        $table = $doc->getElementById("stats");
        $rows = $table->getElementsByTagName("tr");

        $data = [];
        foreach ($rows as $row) {
            $cols = $row->getElementsByTagName("td");
            if ($cols->length === 2) {
                $key = trim($cols->item(0)->nodeValue);
                $value = trim($cols->item(1)->nodeValue);
                $data[$key] = $value;
            }
        }

        return $data;
    }

    // --------------- Public API Methods ---------------

    public function set_cpanel_url($url = "")
    {
        $this->check_for_empty_params(compact("url"));
        $this->cpanel_url = $url;
        return true;
    }

    public function approve_notification()
    {
        $this->check_login();
        $this->simple_curl($this->cpanel_url . "/panel/approve.php",true,["submit" => true],false,[$this->cookie]);
        return true;
    }

    public function disapprove_notification()
    {
        $this->check_login();
        $this->simple_curl($this->cpanel_url . "/panel/disapprove.php", true, ["submit"=>false], false, [$this->cookie]);
        return true;
    }

    public function login($username = "", $password = "", $theme = "PaperLantern")
    {
        $this->check_cpanel_url();
        $this->check_for_empty_params(compact("username", "password"));
        $login = $this->simple_curl(
            $this->cpanel_url . "/login.php",
            true,
            [
                "uname" => $username,
                "passwd" => $password,
                "theme" => $theme,
                "seeesurf" => "567811917014474432",
            ],
            true,
            [],
            true
        );
        preg_match_all("/^Set-Cookie:\s*([^;]*)/mi", $login, $matches);
        $cookies = [];
        foreach ($matches[1] as $item) {
            parse_str($item, $cookie);
            $cookies = array_merge($cookies, $cookie);
        }
        if ($this->logged_in === true) {
            throw new Exception("You are already logged in.");
        }
        if (empty($cookies[$this->vistapanel_session_name])) {
            throw new Exception("Unable to login.");
        }
        if (str_contains($login, "panel/index_pl_sus.php")) {
            throw new Exception("Your account is suspended.");
        }
        if (!str_contains($login, "document.location.href = 'panel/indexpl.php")) {
            throw new Exception("Invalid login credentials.");
        }
        $this->logged_in = true;
        $this->account_username = $username;
        $this->vistapanel_session = $cookies[$this->vistapanel_session_name];
        $this->cookie ="Cookie: " . $this->vistapanel_session_name . "=" . $this->vistapanel_session;
        $notice = $this->simple_curl($this->cpanel_url . "/panel/indexpl.php", false, [], false, [$this->cookie]);
        if (str_contains($notice, "Please click 'I Approve' below to allow us.")) {
            throw new Exception("Please approve or disapprove notifications first.");
        }
        return true;
    }

    public function set_session($session = "")
    {
        $this->check_for_empty_params(compact("session"));
        $this->vistapanel_session = $session;
        $this->cookie ="Cookie: " . $this->vistapanel_session_name . "=" . $this->vistapanel_session;
        if (!$this->logged_in) {
            $this->logged_in = true;
        }
        return true;
    }

    public function create_database($dbname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("dbname"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=mysql&cmd=create",
            true,
            ["db" => $dbname],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function list_databases()
    {
        $databases = [];
        $a_data_table_detail_html = $this->get_table_elements($this->cpanel_url . "/panel/indexpl.php?option=pma");
        foreach ($a_data_table_detail_html as $database) {
            $databases[] = str_replace($this->account_username . "_", "", array_shift($database));
        }
        return $databases;
    }

    public function delete_database($database = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("database"));
        if (!in_array($database, $this->list_databases())) {
            throw new Exception("The database " . $database . " doesn't exist.");
        }
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=mysql&cmd=remove",
            true,
            [
                "toremove" => $this->account_username . "_" . $database,
                "Submit2" => "Remove Database",
            ],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function get_phpmyadmin_link($database = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("database"));
        if (!array_key_exists($database, $this->list_databases())) {
            throw new Exception("The database " . $database . " doesn't exist.");
        }
        $html = $this->simple_curl($this->cpanel_url."/panel/indexpl.php?option=pma", false, [], false, [$this->cookie]);
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        $links = $dom->getElementsByTagName("a");
        foreach ($links as $link) {
            if (str_contains($link->getAttribute("href"), "&db=" . $this->account_username . "_" . $database)) {
                return $link->getAttribute("href");
            }
        }
    }

    public function list_domains($option = "all")
    {
        $this->check_login();
        switch ($option) {
            case "sub":
                $option = "subdomains";
                $id = "subdomaintbl";
                break;
            case "parked":
                $option = "parked";
                $id = "parkeddomaintbl";
                break;
            case "addon":
                $option = "domains";
                $id = "subdomaintbl";
                break;
            default:
                $option = "ssl";
                $id = "sql_db_tbl";
                break;
        }
        $domains = [];
        $a_data_table_detail_html = $this->get_table_elements(
            $this->cpanel_url . "/panel/indexpl.php?option={$option}&ttt=" . $this->get_token(), $id
        );
        foreach ($a_data_table_detail_html as $domain) {
            $domains[] = array_shift($domain);
        }
        return $domains;
    }

    public function create_redirect($domainname = "", $target = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname", "target"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=redirect_add",
            true,
            [
                "domain_name" => $domainname,
                "redirect_url" => $target,
            ],
            false,
            [$this->cookie],
            true
        );
        return true;
    }

    public function delete_redirect($domainname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=redirect_rem&domain=" . $domainname . "&redirect_url=http://",
            true,
            [],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function show_redirect($domainname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=redirect_configure",
            true,
            ["domain_name" => $domainname],
            false,
            [$this->cookie]
        );
        $xpath = '//*[@id="content"]/div/div[1]/table/tbody/tr[2]/td[1]/b[2]';
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        $domxpath = new DOMXPath($dom);
        $values = $domxpath->query($xpath);
        return $values->item(0)->nodeValue;
    }

    public function get_private_key($domainname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=sslconfigure&domain_name=" . $domainname,
            false,
            [],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        $xpath = new DOMXPath($dom);
        $privatekeys = $xpath->query("//textarea[@name='key']");
        return $privatekeys->item(0)->nodeValue;
    }

    public function get_certificate($domainname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=sslconfigure&domain_name=" . $domainname,
            false,
            [],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        $xpath = new DOMXPath($dom);
        $certificates = $xpath->query("//textarea[@name='cert']");
        return $certificates->item(0)->nodeValue;
    }

    public function upload_private_key($domainname = "", $key = "", $csr = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname", "key"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/modules-new/sslconfigure/uploadkey.php",
            true,
            [
                "domain_name" => $domainname,
                "csr" => $csr,
                "key" => $key,
            ],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function upload_certificate($domainname = "", $cert = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname", "cert"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/modules-new/sslconfigure/uploadcert.php",
            true,
            [
                "domain_name" => $domainname,
                "cert" => $cert,
            ],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function delete_certificate($domainname = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $this->simple_curl(
            $this->cpanel_url .
                "/panel/modules-new/sslconfigure/deletecert.php" .
                "?domain_name=" .
                $domainname .
                "&username=" .
                $this->account_username,
            false,
            [],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function get_softaculous_link()
    {
        $this->check_login();
        $getlink = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=installer&ttt=" . $this->get_token(),
            false,
            [],
            true,
            [$this->cookie],
            true
        );
        if (preg_match("~Location: (.*)~i", $getlink, $match)) {
            $location = trim($match[1]);
        }
        return $location;
    }

    public function show_error_page($domainname = "", $option = "400")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $xpath = '//input[@name="' . $option . '"]';
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=errorpages_configure",
            true,
            ["domain_name" => $domainname],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);

        $domxpath = new DOMXPath($dom);

        $values = $domxpath->query($xpath);
        return $values->item(0)->getAttribute("value");
    }

    public function update_error_pages($domainname = "", $v400 = "", $v401 = "", $v403 = "", $v404 = "", $v503 = "") {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=errorpages_change",
            true,
            [
                "domain_name" => $domainname,
                "400" => $v400,
                "401" => $v401,
                "403" => $v403,
                "404" => $v404,
                "503" => $v503
            ],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function show_php_config($domainname = "", $option = "display_errors")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        if ($option !== "date_timezone") {
            $xpath = '//input[@name="' . $option . '"]';
        } else {
            $xpath = "//select[@name='date_timezone']/option[@selected]";
        }
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=phpchangeconfig_configure",
            true,
            ["domain_name" => $domainname],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        $domxpath = new DOMXPath($dom);
        $values = $domxpath->query($xpath);

        switch($option) {
            case "mbstring_http_input":
                return $values->item(0)->getAttribute("value");
            case "date_timezone":
                return $values->item(0)->nodeValue;
            default:
                return $values->item(1)->getAttribute("checked");
        }
    }

    public function set_php_config($domainname = "", $displayerrors = "", $mbstringinput = "", $timezone = "")
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domainname"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=phpchangeconfig_change",
            true,
            [
                "domain_name" => $domainname,
                "display_errors" => $displayerrors,
                "mbstring_http_input" => $mbstringinput,
                "date_timezone" => $timezone,
            ],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function get_user_stats($option = "")
    {
        if (!empty($option) && !str_ends_with($option, ":")) {
            $option = $option . ":";
        }

        $stats = $this->table_to_array(
            $this->simple_curl($this->cpanel_url . "/panel/indexpl.php", true, null, false, [$this->cookie])
        );
        $stats["MySQL Databases:"] = substr($stats["MySQL Databases:"], 0, -1);
        $stats["Parked Domains:"] = substr($stats["Parked Domains:"], 0, -1);
        $stats["Bandwidth used:"] = preg_replace('/MB\\n.{1,50}/i', 'MB', $stats["Bandwidth used:"]);
        $stats = preg_replace('/\\\n.{1,20}",/i', '",', json_encode($stats));
        $stats = json_decode($stats,true);

        if (empty($option)) {
            return $stats;
        } else {
            return $stats[$option];
        }
    }

    public function get_cname_records()
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=cnamerecords&ttt=" . $this->get_token(),
            false,
            null,
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        $dom->loadHTML($html);
        $rows = $dom->getElementsByTagName('tr');

        $array = [];
        for ($i = 2; $i < $rows->length; $i++) {
            $row = $rows->item($i);
            $cols = $row->getElementsByTagName('td');
            $cname = $cols->item(0)->nodeValue;
            if(!isset($cname)) continue;
            $destination = $cols->item(1)->nodeValue;
            $array[] = [
                'Record' => $cname,
                'Destination' => $destination,
            ];
        }
        return $array;
    }

    public function create_cname_record($source, $domain, $dest) {
        $this->check_login();
        $this->check_for_empty_params(compact("source", "domain", "dest"));
        $this->simple_curl(
            $this->cpanel_url . "/panel/modules-new/cnamerecords/add.php",
            true,
            [
                "source" => $source,
                "d_name" => $domain,
                "destination" => $dest,
            ],
            false,
            [$this->cookie],
            true
        );
        return true;
    }

    private function get_cname_deletion_link($source)
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=cnamerecords&ttt=" . $this->get_token(),
            false,
            [],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        $anchor_tags = $dom->getElementsByTagName('a');
        foreach ($anchor_tags as $anchor_tag) {
             if (str_contains($anchor_tag->getAttribute('href'), '?site=' . $source)) {
                 return $anchor_tag->getAttribute('href');
             }
        }
    }

    public function delete_cname_record($source)
    {
        $this->check_login();
        $link = $this->get_cname_deletion_link($source);
        $this->simple_curl(
            $this->cpanel_url . '/panel/' . $link,
            false,
            [],
            false,
            [$this->cookie]
        );
        return true;
    }

    public function get_mx_records()
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=mxrecords&ttt=" . $this->get_token(),
            false,
            null,
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        $dom->loadHTML($html);
        $rows = $dom->getElementsByTagName('tr');

        $array = [];
        for ($i = 2; $i < $rows->length; $i++) {
            $row = $rows->item($i);
            $cols = $row->getElementsByTagName('td');
            $domain = $cols->item(0)->nodeValue;
            if(!isset($domain)) continue;
            $mx = $cols->item(1)->nodeValue;
            $priority = $cols->item(2)->nodeValue;
            $array[] = [
                'Domain' => $domain,
                'MX' => $mx,
                'Priority' => $priority,
            ];
        }
        return $array;
    }

    public function create_mx_record($domain, $server, $priority)
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domain", "server"));
        if(in_array(["Domain" => $domain, "MX" => $server . ".", "Priority" => $priority], $this->get_mx_records())) {
            throw new Exception("Duplicate MX Record detected, please delete the old one first.");
        }
        $this->simple_curl(
            $this->cpanel_url . "/panel/modules-new/mxrecords/add.php",
            true,
            [
                "d_name" => $domain,
                "Data" => $server,
                "Preference" => $priority,
            ],
            false,
            [$this->cookie],
            true
        );
        return true;
    }

    private function get_mx_deletion_link($domain, $srv, $priority)
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=mxrecords&ttt=" . $this->get_token(),
            false,
            [],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        $anchor_tags = $dom->getElementsByTagName('a');
        foreach ($anchor_tags as $anchor_tag) {
             if (
                str_contains($anchor_tag->getAttribute('href'), '?site=' . $domain)
                &&
                str_contains($anchor_tag->getAttribute('href'), '&data=' . $srv)
                &&
                str_contains($anchor_tag->getAttribute('href'), '&aux=' . $priority)
             ) {
                 return $anchor_tag->getAttribute('href');
             }
        }
    }

    public function delete_mx_record($domain, $srv, $priority)
    {
        $this->check_login();
        $link = $this->get_mx_deletion_link($domain, $srv, $priority);
        $this->simple_curl($this->cpanel_url . '/panel/' . $link, false, [], false, [$this->cookie]);
        return true;
    }

    public function get_spf_records()
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=spfrecords&ttt=" . $this->get_token(),
            false,
            null,
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        $dom->loadHTML($html);
        $rows = $dom->getElementsByTagName('tr');

        $array = [];
        for ($i = 2; $i < $rows->length; $i++) {
            $row = $rows->item($i);
            $cols = $row->getElementsByTagName('td');
            $domain = $cols->item(0)->nodeValue;
            if(!isset($domain)) continue;
            $data = $cols->item(1)->nodeValue;
            $array[] = [
                'Domain' => $domain,
                'Data' => $data,
            ];
        }

        return $array;
    }

    public function create_spf_record($domain, $data)
    {
        $this->check_login();
        $this->check_for_empty_params(compact("domain", "data"));
        if(in_array(["Domain" => $domain, "Data" => $data], $this->get_spf_records(), true)) {
            throw new Exception("Duplicate SPF Record detected, please delete the old one first.");
        }
        $this->simple_curl(
            $this->cpanel_url . "/panel/modules-new/spfrecords/add.php",
            true,
            [
                "d_name" => $domain,
                "Data" => $data,
            ],
            false,
            [$this->cookie],
            true
        );
        return true;
    }

    private function get_spf_deletion_link($domain, $data)
    {
        $this->check_login();
        $html = $this->simple_curl(
            $this->cpanel_url . "/panel/indexpl.php?option=spfrecords&ttt=" . $this->get_token(),
            false,
            [],
            false,
            [$this->cookie]
        );
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        $anchor_tags = $dom->getElementsByTagName('a');
        foreach ($anchor_tags as $anchor_tag) {
             if (
                str_contains($anchor_tag->getAttribute('href'), '?site=' . $domain)
                &&
                str_contains($anchor_tag->getAttribute('href'), '&data=' . $data)
             ) {
                 return $anchor_tag->getAttribute('href');
             }
        }
    }

    public function delete_spf_record($domain, $data) {
        $this->check_login();
        $link = $this->get_spf_deletion_link($domain, $data);
        $this->simple_curl($this->cpanel_url . '/panel/' . $link, false, [], false, [$this->cookie]);
        return true;
    }

    public function change_email($new_email, $confirm_email)
    {
        $this->check_login();
        $url = $this->cpanel_url . "/panel/indexpl.php?option=changeemail&ttt=" . $this->get_token();
        $post_data = [
            "ttt" => $this->get_token(),
            "newemail" => $new_email,
            "confemail" => $confirm_email,
        ];
        $this->simple_curl($url, true, $post_data, false, [$this->cookie]);
        return true;
    }

    public function add_password_protection_to_folder($domain_name, $folder_name, $password)
    {
        $this->check_login();
        $post_data = [
            'folder' => $folder_name,
            'domain_name' => $domain_name,
            'password' => $password,
        ];
        $this->simple_curl(
            $this->cpanel_url . '/panel/indexpl.php?option=protectedfolders_configure_2',
            true,
            $post_data,
            false,
            [$this->cookie]
        );
        return true;
    }

    public function create_dns_record($record_type, $domain, $data, $destination = null, $priority = null) {
        $this->check_login();
        $this->check_for_empty_params(compact("domain", "data"));

        switch ($record_type) {
            case 'MX':
                $endpoint = $this->cpanel_url . "/panel/modules-new/mxrecords/add.php";
                break;
            case 'SPF':
                $endpoint = $this->cpanel_url . "/panel/modules-new/spfrecords/add.php";
                break;
            case 'CNAME':
                $endpoint = $this->cpanel_url . "/panel/modules-new/cnamerecords/add.php";
                break;
            default:
                throw new Exception("Unsupported record type: {$record_type}");
        }

        $request_data = [
            "d_name" => $domain,
            "Data" => $data,
        ];

        if ($record_type === 'MX' && !is_null($priority)) {
            $request_data["Preference"] = $priority;
        }
        if ($record_type === 'CNAME' && !is_null($destination)) {
            $request_data["Cname"] = $destination;
        }

        $this->simple_curl(
            $endpoint,
            true,
            $request_data,
            false,
            [$this->cookie],
            true
        );

        return true;
    }

    public function logout()
    {
        $this->check_login();
        $this->simple_curl($this->cpanel_url . "/panel/indexpl.php?option=signout", false, [], false, [$this->cookie]);
        $this->logged_in = false;
        $this->vistapanel_session = "";
        $this->account_username = "";
        $this->cookie = "";
        return true;
    }
}
