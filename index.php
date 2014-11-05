<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" >
<head>
	<title>Encrypted Pastebin - Keep your data private and secure! - Defuse Security</title>
	<meta name="description" content="An Encrypted, Anonymous, Secure, and PRIVATE Pastebin. Send large amounts of text to your friends without it being leaked onto the internet!" />
	<meta name="keywords" content="private pastebin, encrypted pastebin, secure pastebin, anonymous pastebin, privacy" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<script type="text/javascript" src="/vendor/jquery/dist/jquery.min.js"></script>
	<link rel="stylesheet" type="text/css" href="/vendor/bootstrap/dist/css/bootstrap.min.css" />
	<link rel="stylesheet" media="all" type="text/css" href="/css/main.css" />
	<!--[if !IE 7]>
		<style type="text/css">
			#wrap {display:table;height:100%}
		</style>
	<![endif]-->
</head>
<body>
	<center><img style="margin-bottom: 10px;" src="/images/secure_pastebin.png" alt="Secure, Encrypted, Anonymous Pastebin. PIE - Pre Internet Encryption" /></center>

	<div style="text-align:center; font-size: 20px;"><b><u>P</u></b>re-<b><u>I</u></b>nternet <b><u>E</u></b>ncryption for Text</div>

	<form id="pasteform" name="pasteform" action="/bin/add.php" method="post">
		<input id="jscrypt" type="hidden" name="jscrypt" value="no" />
		<br />
		<textarea id="paste" style="color:black; background-color:white; border:dashed 1px black; width:100%;" rows="30" cols="40" name="paste" spellcheck="false"></textarea>
		<br />
		<p><b>All posts are automatically deleted after 10 days.</b></p>
		<input style="width:300px;" type="submit" name="submitpaste" value="Post Without Password Encryption" />
		<input type="checkbox" name="shorturl" value="yes" /> Use shorter URL.
		<input type="checkbox" name="burnread" value="yes" /> Burn after reading.
		 Expire in
		 <select name="lifetime">
			 <option value="31104000">1 Year</option>
			 <option value="15552000">6 Months</option>
			 <option value="2592000">1 Month</option>
			 <option value="864000">10 Days</option>
			 <option value="86400" selected="selected">1 Day</option>
			 <option value="3600">1 Hour</option>
			 <option value="1800">30 Minutes</option>
			 <option value="600">10 Minutes</option>
			 <option value="180">3 Minutes</option>
		 </select>
	</form>


	<!--Client-side encryption options-->
	<noscript><p style="color: #550000;"><b>JavaScript is required to use client-side encryption.</b></p></noscript>
	<div id="encinfo" style="margin-top: 10px;">
		Client-Side Password: 
		<input type="password" id="pass1" value="" /> &nbsp;
		Verify: <input type="password" id="pass2" value="" /> 
		<input type="button" value="Encrypt &amp; Post" onclick="encryptPaste()" />
	</div> <!-- /enc -->
	<!--end of client-side encryption options-->

	<!-- Scripts for client-side encryption -->
	<script type="text/javascript" src="/vendor/sjcl/sjcl.js"></script>
	<script type="text/javascript" src="/js/encrypt.js"></script>

	<script type="text/javascript">
	<!--

	/* Use server-side code to fill this with a random 256 bit hex string. */
	var entropy = "<?php echo bin2hex(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM)); ?>";
	sjcl.random.addEntropy(entropy, entropy.length * 4, "server");

	/* Collect entropy from mouse movements and key-presses */
	try {
		sjcl.random.startCollectors();
	} catch (e) {
		/* Ignore it -- server entropy is good enough. */
	}

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
	<!-- End of scripts for client-side encryption -->
	<a name="security"></a>
	<h2>Security &amp; Encryption Details</h2>

	<p>
	Pastebins are useful for sending text over Twitter or instant messaging, but the
	most popular ones do not provide any security. Posts on "pastebin.com" are
	indexed by search engines. You can
	<a href="https://encrypted.google.com/search?q=%22BEGIN%2bRSA%2bPRIVATE%2bKEY%22%2b%2bsite%3Apastebin.com" rel="nofollow">search for private keys</a>.
	This pastebin aims to protect your data as much as possible while being as easy
	to use as other pastebin services.
	</p>

	<p>
	The text you submit here will be encrypted and sent over an SSL/TLS connection
	so that it should never be seen by anyone unless they know the URL and, if one
	was used, the client-side password. For maximum security, use a strong
	client-side password and transmit it through a secure channel (such as
	OTR-encrypted chat or PGP-encrypted email).
	</p>

	<p>
	<b>Important Security Note:</b>&nbsp; Someone with access to the web server will not be able to
	decrypt the posts already stored in the database, but they <em>can</em>:
	</p>

	<ul>
		<li>Modify the JavaScript encryption code to make it save your password.</li>
		<li>View your post as it is being submitted.</li>
		<li>View your post as it is being viewed.</li>
	</ul>

	<p>
	This means that you must trust the operator of the server hosting this website.
	You must trust that law enforcement has not compelled the operator to provide
	the decrypted posts. So far, that has not happened (check often to see if this
	text has been removed).
	</p>

	<p>
	We have a <a href="/robots.txt">robots.txt</a> entry to stop search engines from
	indexing the posts. Search engines can ignore the robots.txt file, so this is
	not guaranteed.
	</p>

	<p>
	If logging were enabled on the server, then the pastebin URLs would be written
	to the log file and the system administrator could see the posts. For this
	reason, access logging is disabled on the server. If access logging must be
	enabled for some reason, there are rules in place to ensure requests with
	pastebin URLs or Referers are not logged.
	</p>

	<p>
	Here's how the encryption works:
	</p>

	<center>
		<b><u>PIE BIN Encryption Process:</u></b>
		<br /><br />
		<img src="/images/pastebin-diagram.png" alt="Secure Pastebin Data Flow Diagram" title="Secure Pastebin Crypto" />
	</center>

	<a name="commandline"></a>
	<h2>Command-Line Script</h2>

	<p>
	This bash script reads standard input, encrypts it, then uploads it to the
	pastebin. It then prints the command to download and decrypt the post.
	</p>

	<p>
	<b>Warning:</b> The download-and-decrypt command contains the encryption
	password.  It will be visible to other users via the process list (ps aux), and
	will be saved in your shell history. For maximum security, omit the --passphrase
	option and paste the password separately.
	</p>

	<div style="text-align: center;">
		<b><a href="/source/makepaste.sh">Download makepaste.sh</a></b>
	</div>

	<p>
	Tip: To send the command over Twitter, put an "$x" between the slashes in
	"https://", like "https:/$x/". Doing so stops Twitter from transforming it into
	a link.
	</p>
</body>