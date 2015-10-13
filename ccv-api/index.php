<?php

//Define our id-key pairs
$applications = array(
    'APP001' => '28e336ac6c9423d946ba02d19c6a2632', //randomly generated app key
);

 
//wrap the whole thing in a try-catch block to catch any wayward exceptions!
try {
    //*UPDATED*
    //get the encrypted request
    $enc_request = $_POST['enc_request'];
     
    //get the provided app id
    $app_id = $_POST['app_id'];
     
    //check first if the app id exists in the list of applications
    if( !isset($applications[$app_id]) ) {
        throw new Exception('Application does not exist!');
    }
     
    //decrypt the request
    $params = json_decode(trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $applications[$app_id], base64_decode($enc_request), MCRYPT_MODE_ECB)));
     
    //check if the request is valid by checking if it's an array and looking for the controller and action
    if( $params == false || isset($params->service) == false || isset($params->action) == false ) {
        throw new Exception('Request is not valid');
    }
     
    //cast it into an array
    $params = (array) $params;

	$service = ucfirst(strtolower($params['service']));
	$action = strtolower($params['action']).'Action';

	$file = './service/'.$service.'.php';
	if(file_exists($file)) {
		include_once $file;
	}
	else {
		throw new Exception('service is inavalid');
	}

	$service = new $service($params);

	if(method_exists($service, $action) == false) {
		throw new Exception('action is inavlid');
	}

	$result = array();
	$result['data'] = $service->$action();
	$result['success'] = true;
	echo json_encode($result, JSON_UNESCAPED_SLASHES);
	exit();
}
catch (Exception $e) {

	$result = array();
	$result['success'] = false;
	$result['errno'] = $e->getMessage();
	echo json_encode($result, JSON_UNESCAPED_SLASHES);
	exit();

}


?>
