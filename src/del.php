<?php
/*
 * This file is part of Defuse Security's Secure Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */

require_once('pastebin.php');

delete_expired_posts();

$deleted = 0;
if(isset($_GET['key']) && isset($_GET['token']))
{
	$urlKey = $_GET['key'];
	if (slow_equals($_GET['token'], get_deletion_token($urlKey))) {
		$deleted = delete_by_key($urlKey);
	}
} 

//redirect user to the view page, regardless urlKey was valid
$http_host = $_SERVER['HTTP_HOST'];
header("Location: http://{$http_host}?_={$urlKey}");

?>