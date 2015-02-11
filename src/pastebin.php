<?php
/*
 * This file is part of Defuse Security's Secure Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */

require_once('PasswordGenerator.php');
require_once('config.php');

date_default_timezone_set("Zulu");

// Database connection
try {
	$db = new PDO($config['db/connStr'], $config['db/user'], $config['db/pass'],
	  array(PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
	);
  // synchronize PHP and MySql timezone
  $db->exec("SET @@session.time_zone='+00:00';");
} catch(PDOException $ex) {
    die(json_encode(array('success' => false, 'message' => 'Unable to connect')));
}
//mysql_connect($config['db/host'], $config['db/user'], $config['db/pass']);
//@mysql_select_db($config['db/user']) or die( "Unable to select database");
unset($config);

// Constants
define("IV_BYTES", 16);
define("SHORT_KEY_LEN", 12);
define("LONG_KEY_LEN", 32);
define("RET_DELAY", 15);

function commit_post($text, $jsCrypt, $burnread, $lifetime_seconds, $short = false)
{
	global $db;
    do {
        $urlKey = PasswordGenerator::getAlphaNumericPassword($short ? SHORT_KEY_LEN : LONG_KEY_LEN);
    } while( retrieve_post( $urlKey ) !== false );

    $id = get_database_id($urlKey);
    $encrypted = Encrypt($text, $urlKey);
    $time = (int)(time() + $lifetime_seconds);

    $stmt = $db->prepare(
        'INSERT INTO pastes (`token`, `data`, `time`, `jscrypt`, `burnread`, `ipaddress`) 
         VALUES (:id, :encrypted, :time, :jsCrypted, :burnread, :ipaddress)'
    );
  $insrt = array(':id' => $id, 
		':encrypted' => $encrypted, 
		':time' => $time, 
		':jsCrypted' => (int)$jsCrypt,
		':burnread'  => (int)$burnread,
    ':ipaddress' => get_client_ip()                 
	);
	$stmt->execute($insrt);

    return $urlKey;
}

function retrieve_post($urlKey)
{
	global $db;
	$query = $db->prepare('SELECT * FROM `pastes` WHERE `token`=?');
  $query->execute(array(get_database_id($urlKey)));
	$cols = $query->fetch(PDO::FETCH_ASSOC);
  
  $viewByAuthor = false;
  $postInfo = array();
  if($cols)
  {
    $postInfo['timeleft'] = $cols['time'] - time();
    $postInfo['jscrypt']  = $cols['jscrypt']  == "1";
    $postInfo['burnread'] = $cols['burnread'] == "1";
    $postInfo['text'] = Decrypt($cols['data'], $urlKey);
    $postInfo['inserted'] = $cols['inserted'];

    // paste has been added within n seconds
    $recetlyAdded = time() - strtotime($cols['inserted']) < 60;
    $viewByAuthor = $cols['ipaddress'] == get_client_ip() && $recetlyAdded;

    if ($viewByAuthor) {
      $postInfo['deleteToken'] = get_deletion_token($urlKey);
    } 
  }
  
  if (!$viewByAuthor && traffic_limiter($urlKey))
  {
    return array('prevent_bruteforce' => true); 
  }

  if (!$viewByAuthor && $cols && $postInfo['burnread'])
  {
      delete_by_key($urlKey);
  }
  
  return $cols !== false ? $postInfo : false;
}

// trafic_limiter : Make sure the IP address makes at most 1 request every RET_DELAY seconds.
// Will return true if IP address made a call less than 10 seconds ago.
function traffic_limiter($urlKey)
{
  global $db;
  
  $query = $db->prepare('SELECT `time` FROM `retrieves` WHERE `ipaddress`=? ORDER BY 1 DESC LIMIT 1');
  $query->execute(array(get_client_ip()));
  $last_ret = $query->fetchColumn();
  
  $logActivity = true; $abuse = false;
  if($last_ret)
  {
    $abuse = time() - strtotime($last_ret) < RET_DELAY;
    if ($abuse) $logActivity = false; // do not write each trial
  }
  
  if ($logActivity)
  {
    $stmt = $db->prepare(
      'INSERT INTO `retrieves` (`token`, `ipaddress`) 
       VALUES (:token, :ipaddress)'
    );
    $stmt->execute(array(
      ':token'     => get_database_id($urlKey),
      ':ipaddress' => get_client_ip()
    ));
  }
  
  return $abuse;
}

function delete_by_key($urlKey)
{
	global $db;
	$cmd = $db->prepare('DELETE FROM `pastes` WHERE token=?');
	$result = $cmd->execute(array(get_database_id($urlKey)));
	return $result;
}

function delete_expired_posts()
{
	global $db;
    $now = time();
    $db->exec("DELETE FROM pastes WHERE time <= '$now'");
}

function get_database_id($urlKey)
{
    return hash_hmac("SHA256", "database_identity", $urlKey, false);
}

function get_encryption_key($urlKey)
{
    return hash_hmac("SHA256", "encryption_key", $urlKey, true);
}

function get_deletion_token($urlKey)
{
	return hash_hmac("SHA256", "deletion_token", $urlKey, false);
}

function Encrypt($data, $keymaterial)
{
	$iv = mcrypt_create_iv(IV_BYTES, MCRYPT_DEV_URANDOM);

    $encrypted = $iv . mcrypt_encrypt(
		MCRYPT_RIJNDAEL_128,
		get_encryption_key($keymaterial),
		$data,
		MCRYPT_MODE_CBC,
		$iv
    );
	//@see: Understanding PHP AES Encryption http://www.chilkatsoft.com/p/php_aes.asp
	return base64_encode($encrypted);
}

function Decrypt($encData, $keymaterial)
{
	$ciphertext = base64_decode($encData);
	$iv = substr($ciphertext, 0, IV_BYTES);
	$encryptedText = substr($ciphertext, IV_BYTES);
	$data = mcrypt_decrypt(
		MCRYPT_RIJNDAEL_128,
		get_encryption_key($keymaterial),
		$encryptedText, 
		MCRYPT_MODE_CBC,
		$iv
	);
	return str_replace("\0", "", $data);
}

// Constant time string comparison.
// (Used to deter time attacks on hmac checking. See section 2.7 of https://defuse.ca/audits/zerobin.htm)
function slow_equals($a, $b)
{
    $diff = strlen($a) ^ strlen($b);
    for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
    {
        $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $diff === 0;
}

function smartslashes($data)
{
	if(get_magic_quotes_gpc())
	{
		return stripslashes($data);
	}
	else
	{
		return $data;
	}
}

// Escapes a string so that it is safe to include into a JavaScript string
// literal.
function js_string_escape($data)
{
    $safe = "";
    for($i = 0; $i < strlen($data); $i++)
    {
        if(ctype_alnum($data[$i]))
            $safe .= $data[$i];
        else
            $safe .= sprintf("\\x%02X", ord($data[$i]));
    }
    return $safe;
}

// Function to get the client IP address
function get_client_ip() {
    $ipaddress = '';
    if (isset($_SERVER['HTTP_CLIENT_IP']))
        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if (isset($_SERVER['HTTP_X_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    else if (isset($_SERVER['HTTP_FORWARDED_FOR']))
        $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    else if (isset($_SERVER['HTTP_FORWARDED']))
        $ipaddress = $_SERVER['HTTP_FORWARDED'];
    else if (isset($_SERVER['REMOTE_ADDR']))
        $ipaddress = $_SERVER['REMOTE_ADDR'];
    else
        $ipaddress = 'UNKNOWN';
    return $ipaddress;
}

?>
