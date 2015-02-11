<?php
/*
 * This file is part of Defuse Security's Secure Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */

require_once('Crypto.php');
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
    //var_dump($ex);
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
        $urlKey = get_encryption_key();
    } while( retrieve_post( $urlKey ) !== false );

    $id = get_database_id($urlKey);
    $encrypted = Encrypt($text, hex2bin($urlKey));
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
    //var_dump($insrt);
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
    $postInfo['text'] = Decrypt($cols['data'], hex2bin($urlKey));
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
  return HKDF('sha256', $urlKey, 16, 'Zero_Knowledge_Paste_Bin|database_identity');
}

function get_deletion_token($urlKey)
{
  return HKDF('sha256', $urlKey, 16, 'Zero_Knowledge_Paste_Bin|deletion_token');
}

function get_encryption_key()
{
  try {
    return bin2hex(Crypto::CreateNewRandomKey());
  } catch (CryptoTestFailedException $ex) {
    die('Cannot safely create a key');
  } catch (CannotPerformOperationException $ex) {
    die('Cannot safely create a key');
  }
}

function Encrypt($data, $key)
{
	try {
    $ciphertext = Crypto::Encrypt($data, $key);
  } catch (CryptoTestFailedException $ex) {
    die('Cannot safely perform encryption');
  } catch (CannotPerformOperationException $ex) {
    die('Cannot safely perform decryption');
  }
	return base64_encode($ciphertext);
}

function Decrypt($ciphertext, $key)
{
  $data = base64_decode($ciphertext);
	try {
    $plaintext = Crypto::Decrypt($data, $key);
  } catch (InvalidCiphertextException $ex) { // VERY IMPORTANT
    die('DANGER! DANGER! The ciphertext has been tampered with!');
  } catch (CryptoTestFailedException $ex) {
    die('Cannot safely perform encryption');
  } catch (CannotPerformOperationException $ex) {
    die('Cannot safely perform decryption');
  }
	return str_replace("\0", "", $plaintext);
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

function HKDF($hash, $ikm, $length, $info = '', $salt = NULL)
{
  // Find the correct digest length.
  $digest_length = strlen(hash_hmac($hash, '', '', true));

  // Sanity-check the desired output length.
  if (empty($length) || !is_int($length) ||
      $length < 0 || $length > 255 * $digest_length) {
    throw new Exception('Invalid digest length');
  }

  // "if [salt] not provided, is set to a string of HashLen zeroes."
  if (is_null($salt)) {
    $salt = str_repeat("\x00", $digest_length);
  }

  // HKDF-Extract:
  // PRK = HMAC-Hash(salt, IKM)
  // The salt is the HMAC key.
  $prk = hash_hmac($hash, $ikm, $salt, true);

  // HKDF-Expand:

  // This check is useless, but it serves as a reminder to the spec.
  if (strlen($prk) < $digest_length) {
    throw new Exception('Cannot perform hash operation');
  }

  // T(0) = ''
  $t = '';
  $last_block = '';
  for ($block_index = 1; strlen($t) < $length; $block_index++) {
    // T(i) = HMAC-Hash(PRK, T(i-1) | info | 0x??)
    $last_block = hash_hmac(
      $hash,
      $last_block . $info . chr($block_index),
      $prk,
      true
    );
    // T = T(1) | T(2) | T(3) | ... | T(N)
    $t .= $last_block;
  }

  // ORM = first L octets of T
  $orm = substr($t, 0, $length);
  if ($orm === FALSE) {
    throw new Exception('Cannot perform substr operation');
  }
  return bin2hex($orm);
}


?>
