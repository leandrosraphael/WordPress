<?php

require_once 'class-ldap-auth-response.php';
	
class Mo_Ldap_Local_Config
{
    function ldap_login($username, $password)
    {

		$username = stripcslashes($username);
		$password = stripcslashes($password);
		
		$authStatus = null;
		
		if(!Mo_Ldap_Local_Util::is_extension_installed('ldap')) {
			$auth_response = new Mo_Ldap_Auth_Response();
			$auth_response->status = false;
			$auth_response->statusMessage = 'LDAP_ERROR';
			$auth_response->userDn = '';
			return $auth_response;

		}
		if(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			$auth_response = new Mo_Ldap_Auth_Response();
			$auth_response->status = false;
			$auth_response->statusMessage = 'OPENSSL_ERROR';
			$auth_response->userDn = '';
			return $auth_response;
		}
		
		$ldapconn = $this->getConnection();		
		if ($ldapconn) {
			$filter = get_option('mo_ldap_local_search_filter') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_search_filter')) : '';
			$search_base_string = get_option('mo_ldap_local_search_base') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_search_base')) : '';
			$ldap_bind_dn = get_option('mo_ldap_local_server_dn') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_dn')) : '';
			$ldap_bind_password = get_option('mo_ldap_local_server_password') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_password')) : '';

            $fname_attribute = strtolower(get_option('mo_ldap_local_fname_attribute'));
            $lname_attribute = strtolower(get_option('mo_ldap_local_lname_attribute'));
            $email_attribute = strtolower(get_option('mo_ldap_local_email_attribute'));
            $phone_attribute = strtolower(get_option('mo_ldap_local_phone_attribute'));
            $search_filter_attribute = strtolower(get_option('Filter_search'));

            $attr = array();
            if (isset($fname_attribute) && !empty($fname_attribute)) {
                array_push($attr,$fname_attribute);
            }
            if (isset($lname_attribute) && !empty($lname_attribute)) {
                array_push($attr,$lname_attribute);
            }
            if (isset($email_attribute) && !empty($email_attribute)) {
                array_push($attr,$email_attribute);
            }
            if (isset($phone_attribute) && !empty($phone_attribute)) {
                array_push($attr,$phone_attribute);
            }
            if (isset($search_filter_attribute) && !empty($search_filter_attribute)) {
                array_push($attr,$search_filter_attribute);
            }

			$wp_options = wp_load_alloptions();
			foreach($wp_options as $option=>$value){
				if(strpos($option, "mo_ldap_local_custom_attribute_") === false){

				} else{
					array_push($attr, $value);
				}
			}
			$filter = str_replace('?', $username, $filter);

			$search_bases = explode(";", $search_base_string);			
			$user_search_result = null;
			$entry = null;
			$info = null;
			if(get_option('mo_ldap_local_use_tls'))
				ldap_start_tls($ldapconn);
			$bind = @ldap_bind($ldapconn, $ldap_bind_dn, $ldap_bind_password);
            $error_no = ldap_errno($ldapconn);
			$err = ldap_error($ldapconn);
            if ($error_no == -1) {
				$auth_response = new Mo_Ldap_Auth_Response();
				$auth_response->status = false;
                $auth_response->statusMessage = 'LDAP_PING_ERROR';
                $auth_response->userDn = '';
                return $auth_response;
            } elseif (strtolower($err) != 'success') {
                $auth_response = new Mo_Ldap_Auth_Response();
                $auth_response->status = false;
                $auth_response->statusMessage = 'LDAP_BIND_ERROR';
				$auth_response->userDn = '';
				return $auth_response;
			}

			for($i = 0 ; $i < sizeof($search_bases) ; $i++){
				if(ldap_search($ldapconn, $search_bases[$i], $filter, $attr))
					$user_search_result = ldap_search($ldapconn, $search_bases[$i], $filter, $attr);
				else{
					$auth_response = new Mo_Ldap_Auth_Response();
					$auth_response->status = false;
                    $auth_response->statusMessage = 'LDAP_USER_SEARCH_ERROR';
					$auth_response->userDn = '';
					return $auth_response;
				}
				$info = ldap_first_entry($ldapconn, $user_search_result);
				$entry = ldap_get_entries($ldapconn, $user_search_result);
				if($info)
					break;
			}
			if($info){
				$userDn = ldap_get_dn($ldapconn, $info);
			} else{
				$auth_response = new Mo_Ldap_Auth_Response();
				$auth_response->status = false;
                $auth_response->statusMessage = 'LDAP_USER_NOT_EXIST';
				$auth_response->userDn = '';
				return $auth_response;
			}
			$authentication_response = $this->authenticate($userDn, $password);
            if ($authentication_response->statusMessage == 'LDAP_USER_BIND_SUCCESS') {
				$attributes_array = array();
				$profile_attributes = array();

				unset($attr[0]);
				unset($attr[1]);
				unset($attr[2]);

				foreach($attr as $attribute){
						$attributes_array['mo_ldap_local_custom_attribute_'.$attribute] = $entry[0][strtolower($attribute)][0];
				}
				
				$authentication_response->attributeList = $attributes_array;

				if(!empty($email_attribute))
					$profile_attributes['mail'] = $entry[0][$email_attribute][0];
				if(!empty($fname_attribute))	
					$profile_attributes['fname'] = $entry[0][$fname_attribute][0];
				if(!empty($lname_attribute))
                	$profile_attributes['lname'] = $entry[0][$lname_attribute][0];
                if(isset($entry[0][$phone_attribute])) {
                    $profile_attributes['phone'] = $entry[0][$phone_attribute][0];
                }

				$authentication_response->profileAttributesList = $profile_attributes;

			}
			return $authentication_response;
		} else{
			$auth_response = new Mo_Ldap_Auth_Response();
			$auth_response->status = false;
			$auth_response->statusMessage = 'ERROR';
			$auth_response->userDn = '';
			return $auth_response;
		}

	}

	function test_connection() {
		
		if(!Mo_Ldap_Local_Util::is_extension_installed('ldap')) {
			return json_encode(array("statusCode"=>'LDAP_ERROR','statusMessage'=>'<a target="_blank" href="http://php.net/manual/en/ldap.installation.php">PHP LDAP extension</a> is not installed or disabled. Please enable it.'));
		} elseif(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			return json_encode(array("statusCode"=>'OPENSSL_ERROR','statusMessage'=>'<a target="_blank" href="http://php.net/manual/en/openssl.installation.php">PHP OpenSSL extension</a> is not installed or disabled. Please enable it.'));
		}
		
		delete_option('mo_ldap_local_server_url_status');
		delete_option('mo_ldap_local_service_account_status');
		$server_name = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : '';

		$ldapconn = $this->getConnection();
		if ($ldapconn) {
			$ldap_bind_dn = get_option('mo_ldap_local_server_dn') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_dn')) : '';
			$ldap_bind_password = get_option('mo_ldap_local_server_password') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_password')) : '';
			if(get_option('mo_ldap_local_use_tls'))
				ldap_start_tls($ldapconn);
			$ldapbind = @ldap_bind($ldapconn, $ldap_bind_dn, $ldap_bind_password);
            $error_no = ldap_errno($ldapconn);
            $err = ldap_error($ldapconn);
            if ($error_no == -1) {
                add_option('mo_ldap_local_server_url_status', 'INVALID', '', 'no');
                add_option('mo_ldap_local_service_account_status', 'INVALID', '', 'no');
                $troubleshooting_url = add_query_arg(array('tab' => 'troubleshooting'), $_SERVER['REQUEST_URI']);
                if (strpos($server_name,"ldaps") !== false) {
                    return json_encode(array("statusCode" => 'PING_ERROR', 'statusMessage' => 'Cannot connect to LDAP Server. It seems that you are trying <b>ldaps</b> connection. <br>1. Make sure you have gone go through the configuration steps mentioned in our <a href="https://www.miniorange.com/guide-to-setup-ldaps-on-windows-server" target="_blank">LDAPS document</a> to connect with LDAP server over LDAPS (LDAP over SSL:636). <br>2. Make sure you have entered correct LDAP server hostname or IP address and if there is a firewall, please open the firewall to allow incoming requests to your LDAP server from your wordpress site IP address and below specified port number.<br> You can also check our <a href='.esc_url($troubleshooting_url).'>Troubleshooting</a> steps. If you still face the same issue then contact us using the support form below.'));
                } else {
                    return json_encode(array("statusCode" => 'PING_ERROR', 'statusMessage' => 'Cannot connect to LDAP Server. Make sure you have entered correct LDAP server hostname or IP address. <br>If there is a firewall, please open the firewall to allow incoming requests to your LDAP server from your wordpress site IP address and below specified port number. <br>You can also check our <a href='.esc_url($troubleshooting_url).'>Troubleshooting</a> steps. If you still face the same issue then contact us using the support form below.'));
                }
            } elseif (strtolower($err) != 'success') {
                add_option('mo_ldap_local_server_url_status', 'VALID', '', 'no');
				add_option( 'mo_ldap_local_service_account_status', 'INVALID', '', 'no');
                return json_encode(array("statusCode" => 'BIND_ERROR', 'statusMessage' => 'Connection to LDAP server is Successful but unable to make authenticated bind to LDAP server. Make sure you have provided correct username or password.'));
            } else {
                add_option('mo_ldap_local_server_url_status', 'VALID', '', 'no');
                add_option('mo_ldap_local_service_account_status', 'VALID', '', 'no');
                return json_encode(array("statusCode" => 'BIND_SUCCESS', 'statusMessage' => 'Connection was established successfully. Please test authentication to verify LDAP User Mapping Configuration.'));
			}
		} else {
			add_option( 'mo_ldap_local_service_account_status', 'INVALID', '', 'no');
            add_option( 'mo_ldap_local_server_url_status', 'INVALID', '', 'no');
            $troubleshooting_url  = add_query_arg(array('tab' => 'troubleshooting'), $_SERVER['REQUEST_URI']);
            return json_encode(array("statusCode" => 'ERROR', 'statusMessage' => 'There was an error in connecting to LDAP Server with the current settings. Make sure you have entered correct LDAP server hostname or IP address and if there is a firewall, please open the firewall to allow incoming requests to your LDAP server from your wordpress site IP address and below specified port number. You can also check our <a href='.esc_url($troubleshooting_url).'>Troubleshooting</a> steps. If you still face the same issue then contact us using the support form below.'));
		}
	}

    function test_authentication($username, $password)
    {

		if(!Mo_Ldap_Local_Util::is_extension_installed('ldap')) {
			return json_encode(array("statusCode"=>'LDAP_ERROR','statusMessage'=>'<a target="_blank" href="http://php.net/manual/en/ldap.installation.php">PHP LDAP extension</a> is not installed or disabled. Please enable it.'));
		} elseif(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			return json_encode(array("statusCode"=>'OPENSSL_ERROR','statusMessage'=>'<a target="_blank" href="http://php.net/manual/en/openssl.installation.php">PHP OpenSSL extension</a> is not installed or disabled. Please enable it.'));
		}
		
        $local_server_url_status = get_option('mo_ldap_local_server_url_status');
        if ($local_server_url_status == 'INVALID') {
			delete_option('mo_ldap_local_server_url_status');
			delete_option('mo_ldap_local_service_account_status');
			add_option( 'mo_ldap_local_server_url_status', 'INVALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_LOCAL_SERVER_NOT_CONFIGURED', 'statusMessage' => 'Make sure you have successfully configured the <b> LDAP connection information </b>'));
		}
			delete_option('mo_ldap_local_user_mapping_status');
			delete_option('mo_ldap_local_username_status');
            delete_option('mo_ldap_local_password_status');
			$auth_response = $this->ldap_login($username, $password);
        if ($auth_response->statusMessage == "LDAP_USER_BIND_SUCCESS") {
					add_option( 'mo_ldap_local_server_url_status', 'VALID', '', 'no');
					add_option( 'mo_ldap_local_service_account_status', 'VALID', '', 'no');
					add_option( 'mo_ldap_local_user_mapping_status', 'VALID', '', 'no');
					add_option( 'mo_ldap_local_username_status', 'VALID', '', 'no');
                    add_option('mo_ldap_local_password_status', 'VALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_USER_BIND_SUCCESS', 'statusMessage' => 'You have successfully configured your LDAP settings.'));
        } elseif ($auth_response->statusMessage == "LDAP_USER_BIND_ERROR") {
                    add_option('mo_ldap_local_user_mapping_status', 'VALID', '', 'no');
                    add_option('mo_ldap_local_username_status', 'VALID', '', 'no');
                    add_option('mo_ldap_local_password_status', 'INVALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_USER_BIND_ERROR', 'statusMessage' => 'User found in the LDAP server but entered password is invalid. Please check your password.'));
        } elseif ($auth_response->statusMessage == "LDAP_USER_SEARCH_ERROR") {
                    add_option('mo_ldap_local_user_mapping_status', 'INVALID', '', 'no');
                    add_option('mo_ldap_local_username_status', 'INVALID', '', 'no');
                    add_option('mo_ldap_local_password_status', 'INVALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_USER_SEARCH_ERROR', 'statusMessage' => 'Error while searching user in LDAP server.'));
        } elseif ($auth_response->statusMessage == "LDAP_USER_NOT_EXIST") {
					add_option( 'mo_ldap_local_user_mapping_status', 'INVALID', '', 'no');
					add_option( 'mo_ldap_local_username_status', 'INVALID', '', 'no');
                    add_option('mo_ldap_local_password_status', 'INVALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_USER_NOT_EXIST', 'statusMessage' => 'Cannot find user <b>' . esc_attr($username) . '</b> in the directory.<br>Possible reasons:<br>1. The <b>search base</b> DN is typed incorrectly. Please verify if that search base is present.<br>2. User is not present in that search base. The user may be present in the directory but in some other <b>Search Base DN</b> and you may have entered a <b>Search Base DN</b> where this users is not present.<br>3. <b>Username Attribute</b> is incorrect - User is present in the search base but the username you are trying is mapped to a different attribute in the Username Attribute. <br>E.g. You may trying with <b>email attribute</b> value and you may have selected <b>samaccountname attribute</b> in the configuration. Please make sure that the right attribute is selected in the <b>Username Attribute</b> (with which you want the authentication to happen).<br> 4. User is actually not present in the search base. Please make sure that the user is present and test with the right user.'));
        } elseif ($auth_response->statusMessage == "ERROR") {
                    add_option('mo_ldap_local_user_mapping_status', 'INVALID', '', 'no');
					add_option( 'mo_ldap_local_username_status', 'INVALID', '', 'no');
                    add_option('mo_ldap_local_password_status', 'INVALID', '', 'no');
            return json_encode(array("statusCode" => 'LDAP_USER_SEARCH_ERROR', 'statusMessage' => 'Error while authenticating user in LDAP server.'));
		}
	}
	
	
	function getConnection() {
		
		if(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			return null;
		}
		
		$server_name = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : ''; 

		$ldapconn = ldap_connect($server_name);	
		if ( version_compare(PHP_VERSION, '5.3.0') >= 0 ) {
			ldap_set_option($ldapconn, LDAP_OPT_NETWORK_TIMEOUT, 5);
		}

		ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);
		return $ldapconn;
	}
	
	function authenticate($userDn, $password) {
		
		if(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			return false;
		}
		
		$server_name = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : ''; 
						
		$ldapconn = ldap_connect($server_name);
		if ( version_compare(PHP_VERSION, '5.3.0') >= 0 ) {
			ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, 5);
		}
	
		ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);
		
		if(get_option('mo_ldap_local_use_tls'))
			ldap_start_tls($ldapconn);
		$ldapbind = @ldap_bind($ldapconn, $userDn, $password);
        $error_no = ldap_errno($ldapconn);
        $err = ldap_error($ldapconn);

        if ($error_no == -1) {
			$auth_response = new Mo_Ldap_Auth_Response();
            $auth_response->status = false;
            $auth_response->statusMessage = 'LDAP_PING_ERROR';
            $auth_response->userDn = '';
			return $auth_response;
        } elseif (strtolower($err) != 'success') {
		$auth_response = new Mo_Ldap_Auth_Response();
		$auth_response->status = false;
            $auth_response->statusMessage = 'LDAP_USER_BIND_ERROR';
            $auth_response->userDn = '';
		return $auth_response;
			} else {
            $auth_response = new Mo_Ldap_Auth_Response();
            $auth_response->status = true;
            $auth_response->statusMessage = 'LDAP_USER_BIND_SUCCESS';
            $auth_response->userDn = $userDn;
            return $auth_response;
		}
	}

    function show_search_bases_list()
    {
        if(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
            return null;
        }

        $server = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : '';
        $ldap_bind_dn = get_option('mo_ldap_local_server_dn') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_dn')) : '';
        $ldap_bind_password = get_option('mo_ldap_local_server_password') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_password')) : '';

        if(Mo_Ldap_Local_Util::is_extension_installed('ldap')) {

            if (version_compare(PHP_VERSION, '5.3.0') >= 0) {
                ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, 5);
            }

            $ldapconn = ldap_connect($server);

            if ($ldapconn) {
                ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
                ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

                $bind = @ldap_bind($ldapconn, $ldap_bind_dn, $ldap_bind_password);
                $possible_search_bases = get_option("mo_ldap_local_search_bases_list");
                $check_ldap_conn = get_option('mo_ldap_local_service_account_status');
                ?>
                <style>
                    table {
                        border-collapse: collapse;
                        width: 100%;
                    }

                    table, th, td {
                        border: 1px solid black;
                    }

                    td {
                        padding: 5px;
                    }
                </style>
                <?php if ($check_ldap_conn == 'VALID') { ?>
                    <div style="color: #3c763d;background-color: #dff0d8; padding:2%;margin-bottom:20px;text-align:center; border:1px solid #AEDB9A; font-size:18pt;">
                        List of Search Base(s)
                    </div>
                    <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/green_check.png'); ?>"/>
                    </div>
                    <span><b> &nbsp; &nbsp; Select your Search Base(s)/Base DNs from the below Search bases list: </b></span></br></br>

                    <div style="font-family:Calibri;padding:0 3%;">
                    <form method="post" action="">
                    <table>

                        <?php

                        $previous_search_bases = Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_search_base'));
                        $search_base_list = array();
                        $result = ldap_read($ldapconn, '', '(objectclass=*)', array('namingContexts'));
                        $data = ldap_get_entries($ldapconn, $result);
                        $count = $data[0]['namingcontexts']['count'];
                        for ($i = 0; $i < $count; $i++) {
                            if ($i == 0) {
                                $base_dn = $data[0]['namingcontexts'][$i];
                            }
                            $valuetext = $data[0]['namingcontexts'][$i];

                            if (strcasecmp($valuetext, $previous_search_bases)==0)
                            {
                                echo "<tr><td><input type='radio' class='select_search_bases' name='select_ldap_search_bases[]' value='$valuetext' checked>" .esc_attr($valuetext). "</td></tr>";
                                array_push($search_base_list, $data[0]['namingcontexts'][$i]);
                            }
                            else
                            {
                                echo "<tr><td><input type='radio' class='select_search_bases' name='select_ldap_search_bases[]' value='$valuetext'>" .esc_attr($valuetext). "</td></tr>";
                                array_push($search_base_list, $data[0]['namingcontexts'][$i]);
                            }

                        }


                        $filter = "(|(objectclass=organizationalUnit)(&(objectClass=top)(cn=users)))";
                        $search_attr = array("dn", "ou");
                        $ldapsearch = ldap_search($ldapconn, $base_dn, $filter, $search_attr);
                        $info = ldap_get_entries($ldapconn, $ldapsearch);

                        for ($i = 0; $i < $info["count"]; $i++) {
                            $textvalue = $info[$i]["dn"];
                            if ((strcasecmp($textvalue, $previous_search_bases))==0)
                            {
                                echo "<tr><td><input type='radio' class='select_search_bases' name='select_ldap_search_bases[]' value='$textvalue' checked>" . esc_attr($textvalue) . "</td></tr>";
                                array_push($search_base_list, $info[$i]["dn"]);
                            }
                            else
                            {
                                echo "<tr><td><input type='radio' class='select_search_bases' name='select_ldap_search_bases[]' value='$textvalue'>" . esc_attr($textvalue) . "</td></tr>";
                                array_push($search_base_list, $info[$i]["dn"]);
                            }
                        }
                        ?></table><br>

                    <div style="margin:3%;display:block;text-align:center;">
                        <table style="border: none; width: 50%">
                            <tr style="border: none;"><td style="border: none;"> <input style="padding:1%;height:30px;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;" id="submitbase" type="submit" value="Submit" name="submitbase">
                                </td>
                                <td style="border: none;"> <input
                                            style="padding:1%;height:30px;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                                            type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
                                </td></tr>
                        </table>
                    </div>
                    </form><?php

                } else { ?>
                    <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                        No Search Base(s) Found
                    </div>
                    <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/>
                    </div>
                    <br><br><span>Please check :</span>
                    <ul>
                        <li>If your LDAP server configuration (LDAP server url, Username & Password) is correct.</li>
                        <li>If you have successfully saved your LDAP Connection Information.</li>
                    </ul><br><br>
                    <div style="margin:3%;display:block;text-align:center;">
                        <input
                                style="margin-top: -45px; padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                                type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
                    </div>
                <?php }?></div><?php
            }
            else {
                ?>
                    <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                        No Search Base(s) Found
                    </div>
                    <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/>
                    </div>
                    <br><br><span>Please check :</span>
                    <ul>
                        <li>If your LDAP server configuration (LDAP server url, Username & Password) is correct.</li>
                        <li>If you have successfully saved your LDAP Connection Information.</li>
                    </ul><br><br>
                    <div style="margin:3%;display:block;text-align:center;">
                        <input
                                style="margin-top: -45px; padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                                type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
                    </div>
                <?php }?></div><?php
        }else{
            ?>
            <h2>Search Base(s) List: </h2>
            <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                No Search Base(s) Found
            </div>
            <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/>
            </div>
            <br>
            <ul>
                <li><span><a target="_blank" href="http://php.net/manual/en/ldap.installation.php">PHP LDAP extension</a> is not installed or is disabled. Please enable it.</span>
            </ul><br>
            <div style="margin:3%;display:block;text-align:center;">
                <input
                        style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                        type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
            </div>
            <?php
        }
        if (isset($_POST['submitbase'])) {
            if (!empty($_POST['select_ldap_search_bases'])) {
                $search_bases = strtolower(sanitize_text_field($_POST['select_ldap_search_bases'][0]));
                update_option('mo_ldap_local_search_base', Mo_Ldap_Local_Util::encrypt($search_bases));

                echo "<script>window.close();
               window.onunload = function(){
               window.opener.location.reload();
            };
        </script>";
            }
            else{
                echo'<span"><script> alert("You have not selected any Search Base.")</script></span>';
            }
        }
        exit();
    }
	
	function test_attribute_configuration($username) {
		if(!Mo_Ldap_Local_Util::is_extension_installed('openssl')) {
			return null;
		}

        if(Mo_Ldap_Local_Util::is_extension_installed('ldap')) {
		$server = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : '';
		$ldap_bind_dn       = get_option('mo_ldap_local_server_dn') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_dn')) : '';
		$ldap_bind_password = get_option('mo_ldap_local_server_password') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_password')) : '';
	
		$search_base_string = get_option('mo_ldap_local_search_base') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_search_base')) : '';
		$search_bases = explode(";", $search_base_string);
		$search_filter = get_option('mo_ldap_local_search_filter') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_search_filter')) : '';
		$search_filter = str_replace('?', $username, $search_filter);

		$email_attribute = strtolower(get_option('mo_ldap_local_email_attribute'));
		$attr = array($email_attribute);

		if(get_option('mo_ldap_local_cust') != '0'){
			$wp_options = wp_load_alloptions();
			foreach($wp_options as $option=>$value){
				if(strpos($option, "mo_ldap_local_custom_attribute_") === false){

				} else{
					array_push($attr, $value);
				}
			}
		}


		if ( version_compare(PHP_VERSION, '5.3.0') >= 0 ) {
			ldap_set_option( null, LDAP_OPT_NETWORK_TIMEOUT, 5);
		}
			
		$ldapconn = ldap_connect($server);

		if ($ldapconn) { 
			ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

			if(get_option('mo_ldap_local_use_tls'))
				ldap_start_tls($ldapconn);
			$bind = @ldap_bind($ldapconn, $ldap_bind_dn, $ldap_bind_password);
			if($bind){

					for($i = 0 ; $i < sizeof($search_bases) ; $i++){
						if(ldap_search($ldapconn, $search_bases[$i], $search_filter, $attr))
							$user_search_result = ldap_search($ldapconn, $search_bases[$i], $search_filter, $attr);
							$info = ldap_first_entry($ldapconn, $user_search_result);
							$entry = ldap_get_entries($ldapconn, $user_search_result);
							
							if($info){
								$dn = ldap_get_dn($ldapconn, $info);
								break;
							}
						else{

						}
						
					}
                ?>
                <style>
                    table {
                        border-collapse: collapse;
                        width: 100%;
                    }
					
                    table, th, td {
                        border: 1px solid black;
				}
				
                    td {
                        padding: 5px;
                    }
            </style>
            <h2>Attribute Mapping Test : </h2>
            <div style="font-family:Calibri;padding:0 3%;">
            <?php if(!empty($dn)){ ?>
                    <div style="color: #3c763d;background-color: #dff0d8; padding:2%;margin-bottom:20px;text-align:center; border:1px solid #AEDB9A; font-size:18pt;">
                        TEST SUCCESSFUL
                    </div>
                    <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/green_check.png'); ?>"/>
                    </div>
            <table>
                <tr>
                    <td style='font-weight:bold;border:2px solid #949090;padding:2%;'>User DN</td>
                    <td style='padding:2%;border:2px solid #949090; word-wrap:break-word;'><?php echo isset($dn) ? esc_attr($dn): '<b style="color:red;">No such attribute found.</b>'; ?></td>
                </tr>
                <?php
                foreach($attr as $attribute){
                    ?><tr>
                    <td style='font-weight:bold;border:2px solid #949090;padding:2%;'><?php echo esc_attr($attribute); ?></td>
                    <td style='padding:2%;border:2px solid #949090; word-wrap:break-word;'>
                        <?php
                        if(isset($entry[0][$attribute][0])){
                            if(isset($entry[0][$attribute]['count'])){
                                for($i=0;$i<$entry[0][$attribute]['count'];$i++)
                                    echo esc_attr($entry[0][$attribute][$i])."<br>";
                            }
                            else
                                echo esc_attr($entry[0][$attribute][0]);
                        } else
                            echo '<b style="color:red;">Mail attribute is not set in LDAP server.</b>';
                        ?>
                    </td>
                    </tr>
                    <?php
                }
                ?>

            </table>
                    <div style="margin:3%;display:block;text-align:center;"><input
                                style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                                type="button" value="Done" onClick="self.close();"/></div>

            <?php } else { ?>
                    <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                        TEST FAILED
                    </div>
                <br><br>
                    <div style="color: #a94442;font-size:14pt; margin-bottom:20px;">
                        <center>WARNING: User is not found in LDAP server.</center>
                    </div>
                <br>
                    <div style="margin:3%;display:block;text-align:center;"><input
                                style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                                type="button" value="Close" onClick="self.close();"/></div>

                <?php }
            }else{?>
                <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                    TEST FAILED
                </div>
                <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/>
                </div>
                <br><br><span>Please check :</span>
                <ul>
                    <li>If your LDAP server configuration (LDAP server url, Username & Password) is correct.</li>
                    <li>If you have successfully saved your LDAP Connection Information.</li>
                </ul><br><br>
                <div style="margin:3%;display:block;text-align:center;">
                    <input
                            style="margin-top: -45px; padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                            type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
                </div>
            <?php } ?>

            <?php exit();
           }  
		   else {
            $info = false;
           }
		}else { ?>
            <h2>Attribute Mapping Test : </h2>
            <div style="font-family:Calibri;padding:0 3%;">
                <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">
                    TEST FAILED
                </div>
            <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;" src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/>
            </div>
            <br>
            <ul>
                <li><span><a target="_blank" href="http://php.net/manual/en/ldap.installation.php">PHP LDAP extension</a> is not installed or is disabled. Please enable it.</span>
            </ul><br>
            <div style="margin:3%;display:block;text-align:center;">
                <input
                        style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"
                        type="button"  id ="searchbase" value="Close" onClick="self.close();"/>
            </div>
            <?php exit();
        }


	}

    function fetch_groups_info($search_base)
    {
        $server = get_option('mo_ldap_local_server_url') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_url')) : '';
        $ldap_bind_dn       = get_option('mo_ldap_local_server_dn') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_dn')) : '';
        $ldap_bind_password = get_option('mo_ldap_local_server_password') ? Mo_Ldap_Local_Util::decrypt(get_option('mo_ldap_local_server_password')) : '';

        $search_filter = '(objectClass=Group)';

        $attr = array('distinguishedname','cn');

        if ( version_compare(PHP_VERSION, '5.3.0') >= 0 ) {
            ldap_set_option( null, LDAP_OPT_NETWORK_TIMEOUT, 5);
        }

        $ldapconn = ldap_connect($server);

        if ($ldapconn) {
            ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);
            if(get_option('mo_ldap_local_use_tls'))
                ldap_start_tls($ldapconn);
            $bind = @ldap_bind($ldapconn, $ldap_bind_dn, $ldap_bind_password);
            if($bind){
                if(ldap_search($ldapconn, $search_base, $search_filter, $attr)) {
                    $user_search_result = ldap_search($ldapconn, $search_base, $search_filter, $attr);
                    $info = ldap_first_entry($ldapconn, $user_search_result);
                    $entry = ldap_get_entries($ldapconn, $user_search_result);
                }
            }?>
            <style>
                table { border-collapse: collapse; width: 100%; }
                table, th, td { border: 1px solid black;}
                td{padding:5px;}
            </style>
            <h2>Groups Results : </h2>
            <div style="font-family:Calibri;padding:0 3%;">
            <?php if($entry['count'] > 1){ ?>
                <div style="color: #3c763d;background-color: #dff0d8; padding:2%;margin-bottom:20px;text-align:center; border:1px solid #AEDB9A; font-size:18pt;">Groups Fetched Successfully</div>
                <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;"src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/green_check.png'); ?>"/></div>
                <div style="color: #3c763d;font-size:14pt; margin-bottom:20px;">You can use following distinguished name of the groups for role mapping configuration in the plugin</div>

                <table>
                    <tr>
                        <td style='font-weight:bold;border:2px solid #949090;padding:2%;'><?php echo "Group Name"; ?></td>
                        <td style='font-weight:bold;border:2px solid #949090;padding:2%;'><?php echo "Distinguished Name"; ?></td>
                    </tr>
                    <?php
                    for ($i=0;$i<$entry['count'];$i++) {
                        ?>
                        <tr>
                            <td style='padding:2%;border:2px solid #949090; word-wrap:break-word;'>
                                <?php
                                if (isset($entry[$i]['cn'][0])) {
                                    echo esc_attr($entry[$i]['cn'][0]);
                                } ?>
                            </td>
                            <td style='padding:2%;border:2px solid #949090; word-wrap:break-word;'>
                                <?php
                                if (isset($entry[$i]['distinguishedname'][0])) {
                                    echo esc_attr($entry[$i]['distinguishedname'][0]);
                                }
                                ?>
                            </td>
                        </tr>
                        <?php
                    }
                    ?>

                </table>
            <?php } else { ?>
                <div style="color: #a94442;background-color: #f2dede;padding: 15px;margin-bottom: 20px;text-align:center;border:1px solid #E6B3B2;font-size:18pt;">No groups exists in the provided search base</div>
                <div style="display:block;text-align:center;margin-bottom:4%;"><img style="width:15%;"src="<?php echo esc_url(plugin_dir_url(__FILE__) . 'includes/images/wrong.png'); ?>"/></div>
            <?php } ?>
            <div style="margin:3%;display:block;text-align:center;"><input style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"type="button" value="Done" onClick="self.close();"/></div>

            <?php exit();
        }
        else {
            $info = false;
        }
    }
}?>