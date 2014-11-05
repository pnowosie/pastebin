<?php
	
    $config = array(
        // application run mode
        'mode' => 'DEBUG',
    
        // application root directory
        'AppDir' => '',
        
        // database prod
        'db/connStr' => '---HOST-GOES-HERE---',
        'db/user' => '---USERNAME---',
        'db/pass' => '---PASSWORD---',
    );
    
    function isDebug()
    {
        global $config;
        return (isset($config['mode']) && $config['mode'] == 'DEBUG');
    } 
	
	function dump($var, $varname=null) 
	{
		if (isDebug()) {
			if (isset($varname)) echo $varname .':'; 
			 var_dump($var); echo '<br/>';
		}
	}

	if (!isDebug()) {
		error_reporting(0);
	}
?>
