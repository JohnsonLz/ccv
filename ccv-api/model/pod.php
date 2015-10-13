<?php 

class POD {

	private $con;

	public function __construct() {
		
	}

	public function connect($host, $db, $user, $password) {

		$con = mysql_connect($host, $user, $password);
		if(!$con) {
			return false;
		}
		mysql_select_db($db, $con);
		return true;;
	}

	public function query($sql) {

		return mysql_query($sql);
	}

	public function close() {

		mysql_close($con);
	}

}

?>
