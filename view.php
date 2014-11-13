<?php
/*
 * This file is part of Defuse Security's Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */
date_default_timezone_set("Zulu");
require_once('src/pastebin.php');

// Never show a post over an insecure connection
/*if($_SERVER["HTTPS"] != "on") {
   header("HTTP/1.1 301 Moved Permanently");
   header("Location: https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"]);
   die();
}*/

delete_expired_posts();

/*
 * Instead of rewrite rules, just handle post retrieval here
 * /view.php?_=postkey
 */
if (!isset($_GET['_'])) {
    echo "Error: Sorry, the paste you were looking for could not be found.";
    die();
}
$urlKey = $_GET['_'];

$postInfo = retrieve_post($urlKey);

if (isset($_GET['raw']) && $_GET['raw'] == "true") {
    header('Content-Type: text/plain');
    if ($postInfo['jscrypt'] == false) {
        echo $postInfo['text'];
    } else {
        echo "ERROR: This paste was encrypted with client-side encryption.";
    }
    die();
}

//Disable caching of viewed posts:
header("Cache-Control: no-cache, must-revalidate"); 
header("Expires: Mon, 01 Jan 1990 00:00:00 GMT"); 

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
  <title>ZeroBin minimalist zero-knowledge pastebin</title>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<link rel="stylesheet" type="text/css" href="/vendor/bootstrap/dist/css/bootstrap.min.css" />
  <link rel="stylesheet" type="text/css" href="/css/main.css" />
</head>
<body>
<div class="container">
  <div class="center-block">
    <h1><a href="/view.php">ZeroBin</a></h1>
    <div class="lead">minimalist opensource zero-knowledge pastebin</div>
  </div>
<?php


if($postInfo !== false)
{
    // Display remaining lifetime
    $timeleft = $postInfo['timeleft'];
    $days = (int)($timeleft / (3600 * 24));
    $hours = (int)($timeleft / (3600)) % 24;
    $minutes = (int)($timeleft / 60) % 60;
    echo "<div id=\"timeleft\">This post will be deleted in $days days, $hours hours, and $minutes minutes.</div>";
	if ($postInfo['burnread']) {
	  echo '<div id="timeleft"><span class="label label-warning">Warning</span> Don\'t close this window, this message can\'t be displayed again.</div>';
	}
	
	if($postInfo['jscrypt'] == false) 
	{
        // If the post wasn't encrypted in JavaScript, we can display it right away
		$split = explode("\n", $postInfo['text']);
		$i = 0;
		echo '<div class="codebox"><ol>';
		foreach($split as $line)
		{
            $line = htmlentities($line, ENT_QUOTES);
			$line = str_replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;", $line);
			$line = str_replace("  ", "&nbsp;&nbsp;", $line);
			echo '<li><div class="div' . $i . '">&nbsp;' . $line . '</div></li>';
			$i = ($i + 1) % 2;
		}
		echo '</ol></div>';
	}
	else 
	{
        // The post was encrypted in JavaScript, so we print a password prompt
		PrintPasswordPrompt(); 

        // JS will fill this div with the decrypted text
		echo '<div id="tofill" class="codebox"></div>';
        
        // JS decryption code
		PrintDecryptor($postInfo['text']);
	}

	?>
	<?php if(isset($postInfo['deleteToken'])) : ?>
	<div>
	  <span class="label label-info">Info</span>
	  To delete this paste use <a href="/src/del.php?key=<?php echo $urlKey; ?>&token=<?php echo $postInfo['deleteToken']; ?>">this link</a>.
	</div>
	<?php endif; ?>
	
	<form name="pasteform" id="pasteform" action="/bin/add.php" method="post">

	<textarea id="paste" name="paste" spellcheck="false" rows="30" cols="80">
    <?php
        if(!$postInfo['jscrypt'])
			    echo htmlentities($postInfo['text'], ENT_QUOTES);
	  ?>
  </textarea>

	<input id="jscrypt" type="hidden" name="jscrypt" value="no" />
	<input style="width:300px;" type="submit" name="submitpaste" value="Post Without Password Encryption" />
	<input type="checkbox" name="shorturl" value="yes" /> Use shorter URL.
     Expire in
     <select name="lifetime">
         <option value="15552000">6 Months</option>
         <option value="2592000">30 Days</option>
         <option value="864000" selected="selected">10 Days</option>
         <option value="86400">1 Day</option>
         <option value="3600">60 Minutes</option>
         <option value="600">10 Minutes</option>
     </select>
    </form>

	<div id="encinfo">
		Password: 
		<input type="password" id="pass1" value="" size="8" /> &nbsp;
		Verify: <input type="password" id="pass2" value="" size="8" /> 
		<input type="button" value="Encrypt &amp; Post" onclick="encryptPaste()" /> 
		<noscript>
			<b>[ Please Enable JavaScript ]</b>
		</noscript>
	</div>
	<?php
}
else // $postInfo === false, the post does not exist.
{
	echo "<div id=\"sorry\">Sorry, the paste you were looking for could not be found.</div>";
}

// ======================== FUNCTIONS ========================
function PrintPasswordPrompt()
{
?>
	<div id="passwordprompt">
        <b>Enter Password:</b> 
        <input type="password" id="password" name="password" value="" /><input type="button" name="decrypt" value="Decrypt" onClick="decryptPaste();" />
        <noscript>
			<b>[ Please Enable JavaScript ]</b>
        </noscript>
    </div>
<?php
}

function PrintDecryptor($data)
{
?>
<script type="text/javascript">
function decryptPaste(){
    try {
        var encrypted = "<? echo js_string_escape($data); ?>";
        var password = document.getElementById("password").value;
        var plaintext = encrypt.decrypt(password, encrypted);
		document.getElementById("passwordprompt").innerHTML = "";

		document.getElementById("paste").value = plaintext;

		var lines = plaintext.split("\n");
		var fancyLines = [];
		var i = 0; 
		fancyLines.push("<ol>");
		for(i = 0; i < lines.length; i++)
		{
			var bgColor = i % 2;
			var line = lines[i].replace("\n", "");
			line = line.replace("\r", "");
			fancyLines.push("<li><div class=\"div" + bgColor + "\">&nbsp;" + encrypt.allhtmlsani(line) + "</div></li>");
		}
		fancyLines.push("</ol>");

		var fill = document.getElementById("tofill");
        fill.style.display = "block";
		fill.innerHTML = fancyLines.join('');

    } catch (e) {
        if (e.constructor == sjcl.exception.corrupt) {
            alert('Wrong password or corrupted/invalid ciphertext.');
        } else {
            alert(e);
        }
    }
}
</script>
<?php
}
?>
<p style="padding: 20px;">
<strong>Important Note:</strong> 
This page contains user-submitted content. In no way site administrator is responsible for its contents.<br/>
This is a test service: Data may be deleted anytime. Kittens will die if you abuse this service.
</p>
</div>
<!-- Scripts required for client-side decryption -->
<script type="text/javascript" src="/vendor/sjcl/sjcl.js"></script>
<script type="text/javascript" src="/js/encrypt.js"></script>

<script type="text/javascript">
<!--
function encryptPaste()
{
	var pass1 = document.getElementById("pass1").value;
	var pass2 = document.getElementById("pass2").value;
	if(pass1 == pass2 && pass1 != "")
	{
		var plain = document.getElementById("paste").value;
		var ct = encrypt.encrypt(pass1, plain);
		document.getElementById("paste").value = ct;
		document.getElementById("jscrypt").value = "yes";
		document.pasteform.submit();
	}
	else if(pass1 != pass2)
	{
		alert("Passwords do not match.");
	}
	else if(pass1 == "")
	{
		alert("You must provide a password.");
	}
}
-->
</script>
<!-- End of scripts for client-side decryption -->

</body>
</html>