<?php
/*
 * This file is part of Defuse Security's Pastebin
 * Find updates at: https://defuse.ca/pastebin.htm
 * Developer contact: havoc AT defuse.ca
 * This code is in the public domain. There is no warranty.
 */
require_once('src/pastebin.php');

delete_expired_posts();

/*
 * Instead of rewrite rules, just handle post retrieval here
 * /view.php?_=postkey
 */
$postInfo = false;
if (isset($_GET['_'])) {

  $urlKey = $_GET['_'];

  $postInfo = retrieve_post($urlKey);

  // prevent bruteforce key search
  if (isset($postInfo['prevent_bruteforce']))
  {
    echo 'Too many frequent requests in a amount of time. Wait a little bit longer and try again.';
    die();
  }
  
  if (isset($_GET['raw'])) {
      header('Content-Type: text/plain');
      echo (isset($postInfo['text']) ? $postInfo['text'] : "Not found $urlKey");
      die();
  }
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
<body onload="init()">
<div class="container">
  <div class="page-header">
    <h1><a href="/">ZeroBin</a></h1>
    <div class="lead">minimalist opensource zero-knowledge pastebin</div>
  </div>
	
  <?php
  if ($postInfo === false && isset($urlKey)) // Unable to find post of given urlkey
  {
    echo "<div><span class=\"label label-danger\">ERROR</span> Sorry, the paste you were looking for could not be found.</div>";
  }

  if($postInfo !== false)
  {
      $inserted = $postInfo['inserted'];
      
      
    if ($postInfo['burnread']) {
      echo '<div id="timeleft"><span class="label label-warning">Warning</span> Don\'t close this window, this message can\'t be displayed again.</div>';
      $lifetime = "immediately after you refresh this window";
    } else {
      // Display remaining lifetime
      $timeleft = $postInfo['timeleft'];
      $days = (int)($timeleft / (3600 * 24));
      $hours = (int)($timeleft / (3600)) % 24;
      $minutes = (int)($timeleft / 60) % 60;
      $lifetime = "in $days days, $hours hours, and $minutes minutes";
    }
    echo "<div id=\"timeleft\">This post was added at $inserted and will be deleted $lifetime.</div>";

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

    <?php
  }

  // ======================== FUNCTIONS ========================
  function PrintPasswordPrompt()
  {
  ?>
    <div id="passwordprompt">
      <b>Enter Password:</b> 
      <input type="password" id="password" name="password" value="" size="50" />
      <input type="button" name="decrypt" value="Decrypt" onClick="decryptPaste();" />
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
  function decryptPaste(key){
      try {
          var encrypted = "<?php echo js_string_escape($data); ?>";
          var password = document.getElementById("password").value;
          if (password.length == 44 && password[43] == '=') // base64 key
            key = sjcl.codec.base64.toBits(password);
          var plaintext = encrypt.decrypt(key || password, encrypted);
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
  

  <div class="row">
    <form name="pasteform" id="pasteform" action="/src/add.php" method="post">
		<div class="col-md-8">
		  <textarea id="paste" name="paste" spellcheck="false" rows="30" cols="80"><?php
				  if(isset($postInfo) && !$postInfo['jscrypt'])
			echo htmlentities($postInfo['text'], ENT_QUOTES);
			?></textarea>
		</div>
		<div class="col-md-4">
		  <p><button class="btn btn-success" type="submit" name="submitpaste">
			<span class="glyphicon glyphicon-floppy-disk" aria-hidden="true"></span>
			Post
		  </button></p>
		  <p><input id="jscrypt" type="hidden" name="jscrypt" value="no" /</p>
		  <p><input type="checkbox" name="shorturl" value="yes" /> Use shorter URL.</p>
		  <p><input type="checkbox" name="burnread" value="yes" /> Burn after reading.</p>
		  <p>Expire in <select name="lifetime">
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
		  </p>
		</div>
	</form>
	</div>
	<div id="encinfo">
		<input type="password" id="pass1" value="" size="15" placeholder="Password" /> &nbsp;
		<input type="password" id="pass2" value="" size="15" placeholder="Confirm" onkeyup="deriveKey()" /> &nbsp;
	<button type="button" class="btn btn-default btn-xs" aria-label="Left Align" onclick="generateKey()">
	  <span class="glyphicon glyphicon-repeat" aria-hidden="true"></span>
	</button>
	<input type="text" id="key" value="" size="50" /> 
		<input type="button" value="Encrypt &amp; Post" onclick="encryptPaste()" /> 
		<noscript>
			<b>[ Please Enable JavaScript ]</b>
		</noscript>
	</div> 


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
		if(encrypt.derived_key != null)
		{
			var plain = document.getElementById("paste").value;
			var ct = encrypt.encrypt(plain);
			document.getElementById("paste").value = ct;
			document.getElementById("jscrypt").value = "yes";
			document.pasteform.submit();
		}
		else
		{
			alert("You must provide a password.");
		}
	}
  
  function generateKey() {
    var pass1 = document.getElementById("pass1");
		var pass2 = document.getElementById("pass2");
    var key = document.getElementById('key');
    pass1.value = pass2.value = '';
    encrypt.session_salt = [];
    encrypt.derived_key = sjcl.random.randomWords(8);
    key.value = sjcl.codec.base64.fromBits(encrypt.derived_key);
    key.select();
  }
  
  function deriveKey() {
    var pass1 = document.getElementById("pass1");
		var pass2 = document.getElementById("pass2");
    
    if (!pass1.value) {
      pass1.focus();
      setTimeout(function() {
        pass2.value = '';
      }, 1);
      return;
    }
    
    if (pass1.value == pass2.value) {
      var key = document.getElementById('key');
      encrypt.session_salt = sjcl.random.randomWords(8);
      encrypt.derived_key = encrypt.derive_key(pass1.value, encrypt.session_salt, 1000);//encrypt.derived_key = ...?
      var derived = sjcl.codec.base64.fromBits(encrypt.derived_key);
      key.value = derived;
      setTimeout(function() {
        pass1.value = ''; pass2.value = '';
        key.select();
      }, 1);
    } else if (pass1.value.length == pass2.value.length) {
      alert("Password doesn't match.");
      setTimeout(function() {
        pass2.value = '';
      }, 1);
    }
  }
  
  function init() {
    var hashIndex = window.location.href.indexOf("#");
    
    if (hashIndex >= 0) {
      var urlkey = window.location.href.substring(hashIndex + 1);
      var key = sjcl.codec.base64.toBits(urlkey);
      if (key.length == 8) {
        decryptPaste(key);
      }
    }
  }
-->
</script>
<!-- End of scripts for client-side decryption -->

</body>
  <!-- Start of StatCounter Code for Default Guide -->
  <script type="text/javascript">
    var sc_project=10137123; 
    var sc_invisible=0; 
    var sc_security="0fa4181f"; 
    var scJsHost = (("https:" == document.location.protocol) ? "https://secure." : "http://www.");
    document.write("<sc"+"ript type='text/javascript' src='" + scJsHost+ "statcounter.com/counter/counter.js'></"+"script>");
  </script>
  <noscript><div class="statcounter"><a title="website statistics" href="http://statcounter.com/" target="_blank"><img class="statcounter" src="http://c.statcounter.com/10137123/0/0fa4181f/0/" alt="website statistics"></a></div>
  </noscript>
  <!-- End of StatCounter Code for Default Guide -->
  <!-- GA code -->
  <script>
    (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
    (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
    m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
    })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

    ga('create', 'UA-56783468-1', 'auto');
    ga('send', 'pageview');
  </script>
</html>
