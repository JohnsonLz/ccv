<?php

class recognize {

	private $params_;

	public function __construct($params) {
		
		this->$arams_ = $params;
	}

	public function recognizreAction() {

		$db = new POD();
		$p = db.connect('localhost', 'root', '283447');
		if(p === false) {
			throw new Exception('Database connect failed');
		}

		$res = db.query('select projectId from Project where projectName = \''.params['project'].'\' ;');
		if(mysql_num_rows(res) == 0) {
			db.close();
			throw new Exception('project doesn\'t exist');
		}

		$row = mysql_fetch_array(res);
		$pid = res['projectId'];

		$res = db.query('select password from User where userName = \''.params[userName].'\' and userId in (select userId from Contributer where projectId = \''.$pid.'\';');
		if(mysql_num_rows(res) == 0) {
			db.close();
			throw new Exception('user has no authority in this project');
		}

		$row = mysql_fetch_array(res);
		if(params['password'] !== row['password']) {
			db.close();
			throw new Exception('password error');
		}

		$res = '/home/lz/Workplace/Repertory/'.params['user'].'/'.params['project'].'/';
		return $res;

	}


}

?>
