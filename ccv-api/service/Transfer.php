<?php

class Transfer {

	private $params_;

	public function __construct($params) {

		$this->params_ = $params;
	}

	public function downloadAction() {
		
		$header = array('content-type: application/x-www-form-urlencoded; charset=UTF-8');
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, 'http://localhost/repertory/'.$this->params_['uri']);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_RANGE, $this->params_['range']);
		curl_setopt($ch, CURLOPT_HTTPHEADER,$header);
		curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1); 
		
		$res = curl_exec($ch);

		if($res == false) {
			$result = array();
			$result['errno'] = curl_error($ch);
			curl_close($ch);
			return $result;
		}

		curl_close($ch);
		$result = array();
		$result['success'] = true;
		$result['data'] = base64_encode($res);
		$result['length'] = strlen($result['data']);
		return $result;
	}

}

?>
