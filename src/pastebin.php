<?php
/*
 * This file is part of Defuse Security's Secure Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */

require_once('PasswordGenerator.php');

// Database connection
require_once('../config.php');
try {
	$db = new PDO($config['db/connStr'], $config['db/user'], $config['db/pass'],
	  array(PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
	);
} catch(PDOException $ex) {
    die(json_encode(array('success' => false, 'message' => 'Unable to connect')));
}
//mysql_connect($config['db/host'], $config['db/user'], $config['db/pass']);
//@mysql_select_db($config['db/user']) or die( "Unable to select database");
unset($config);

// Constants
define("IV_BYTES", 16);

function commit_post($text, $jsCrypt, $lifetime_seconds, $short = false)
{
	global $db;
	dump($db, '$db');
    do {
        $urlKey = PasswordGenerator::getAlphaNumericPassword($short ? 8 : 22);
    } while( retrieve_post( $urlKey ) !== false );

    $id = get_database_id($urlKey);
    $encryptionKey = get_encryption_key($urlKey);

    $iv = mcrypt_create_iv(IV_BYTES, MCRYPT_DEV_URANDOM);

    $encrypted = SafeEncode(
        $iv .
        mcrypt_encrypt(
            MCRYPT_RIJNDAEL_128,
            $encryptionKey,
            $text,
            MCRYPT_MODE_CBC,
            $iv
        )
    );

    $jsCrypted = $jsCrypt ? 1 : 0;
    $time = (int)(time() + $lifetime_seconds);

    $stmt = $db->prepare(
        "INSERT INTO pastes (token, data, time, jscrypt) 
         VALUES (:id, :encrypted, :time, :jsCrypted)"
    );
	$stmt->execute(array(':id' => $id, ':encrypted' => $encrypted, ':time' => $time, ':jsCrypted' => $jsCrypted));

    return $urlKey;
}

function retrieve_post($urlKey)
{
	global $db;
	$query = $db->prepare("SELECT * FROM `pastes` WHERE token=?");
    $query->execute(array(get_database_id($urlKey)));
	$cols = $query->fetch(PDO::FETCH_ASSOC);
    if($cols)
    {
        $postInfo = array();
        $postInfo['timeleft'] = $cols['time'] - time();
        $postInfo['jscrypt'] = $cols['jscrypt'] == "1";

        $encryptionKey = get_encryption_key($urlKey);
        $ciphertext = SafeDecode($cols['data']);
        $iv = substr($ciphertext, 0, IV_BYTES);
        $encryptedText = substr($ciphertext, IV_BYTES);
        $postInfo['text'] = 
            str_replace("\0", "",
                mcrypt_decrypt(
                    MCRYPT_RIJNDAEL_128,
                    $encryptionKey,
                    $encryptedText, 
                    MCRYPT_MODE_CBC,
                    $iv
                )
            );
        return $postInfo;
    }
    else
        return false;
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

function SafeEncode($data)
{
	return base64_encode($data);
}

function SafeDecode($data)
{
	return base64_decode($data);
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

?>
