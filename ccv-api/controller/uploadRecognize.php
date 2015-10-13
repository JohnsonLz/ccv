<?php

session_start();
include_once 'apiCaller.php';

$apiCaller = new apiCaller('APP001', '28e336ac6c9423d946ba02d19c6a2632', 'http://localhost/ccv-api/');

$result  = $apiCaller->sendRequest(array(
	'service' => 'Recognize',
	'action' => 'recognize',
	'userName' => $_POST['userName'];
	'password' => $_POST['password'];
	'project' => $_POST['project'];
));

//todo:: 

?>
