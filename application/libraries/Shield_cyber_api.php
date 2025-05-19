<?php 
defined('BASEPATH') OR exit('No direct script access allowed');

class Shield_cyber_api 
{
	private $ch;
	private $redis_host;
	private $redis_port;
	private $redis_timeout;  
	private $redis_password;
	private $client_redis_key;
	private $page_size;

	public function __construct()
	{
		$CI =& get_instance();

		$this->redis_host       = $CI->config->item('redis_host');
		$this->redis_port       = $CI->config->item('redis_port');
		$this->redis_timeout    = $CI->config->item('redis_timeout');
		$this->redis_password   = $CI->config->item('redis_password');
		$this->client_redis_key = 'shield_cyber_';
		$this->page_size        = $CI->config->item('shield_cyber_page_size') ?? 10;  // The limit of results per call, between 1 - 1000, defaults to 100.
	}

	public function redis_info($client, $field = NULL, $action = 'GET', $data = NULL)
	{
		$client_info    = client_redis_info($client);
		$client_key     = $this->client_redis_key.$client;

		$redis = new Redis();
		$redis->connect($client_info['redis_host'], $client_info['redis_port'], $this->redis_timeout);
		$redis->auth($client_info['redis_password']);

		if ($action === 'SET')
		{
			$check = $redis->hMSet($client_key, $data);
		}
		else
		{
			if (is_null($field))
			{
				$check = $redis->hGetAll($client_key);
			}
			else
			{
				$check = $redis->hGet($client_key, $field);
			}
		}     

		$redis->close();

		if (empty($check))
		{
			$check = NULL;
		}

		return $check;		
	}

	public function create_shield_cyber_redis_key($client, $data = NULL)
	{
		$client_info    = client_redis_info($client);
		$client_key     = $this->client_redis_key.$client;

		$redis = new Redis();
		$redis->connect($client_info['redis_host'], $client_info['redis_port'], $this->redis_timeout);
		$redis->auth($client_info['redis_password']);

		$check = $redis->hMSet($client_key, [
			'hostname'          => $data['hostname'],
			'subscription_id'   => $data['subscription_id'],
			'api_key'           => $data['api_key'],
			'tested'            => '0',
			'request_sent'      => '0',
			'enabled'           => '0',
			'terms_agreed'      => '0'
		]);

		$redis->close();

		return $check;		
	}

	public function get_attack_surface_vulns($client, $filter_params)
	{
		$result = [];

		$response = $this->get_attack_surface_vulnerabilities($client, $filter_params);

		if ($response['success'])
		{
			$vuln_count = count($response['response']);

			if ($vuln_count)
			{
				$result['vulnerabilities']  = $response['response'];
				$result['vuln_count']       = $vuln_count;

				if ($vuln_count > 1)
				{
					usort($result['vulnerabilities'], function($a, $b) 
					{
						return $b['cvss'] <=> $a['cvss'];
					});
				}

				if ($vuln_count > $this->page_size)
				{
					$result['vulnerabilities']  = array_slice($result['vulnerabilities'], 0, $this->page_size);
					$result['vuln_count']       = $this->page_size;
				}

				return array(
					'success'   => TRUE,
					'response'  => $result
				);
			}
			else
			{
				return array(
					'success'   => FALSE,
					'response'  => array(
						'message'   => 'get_attack_surface_vulnerabilities() returned zero results'
					)
				);
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => $response['response']
			);
		}
	}

	public function get_internal_network_vulns($client, $filter_params)
	{
		$result = [];

		$response = $this->get_internal_network_vulnerabilities($client, $filter_params);

		if ($response['success'])
		{
			$vuln_count = count($response['response']);

			if ($vuln_count)
			{
				$result['vulnerabilities']  = $response['response'];
				$result['vuln_count']       = $vuln_count;

				if ($vuln_count > 1)
				{
					usort($result['vulnerabilities'], function($a, $b) 
					{
						return $b['cvss'] <=> $a['cvss'];
					});
				}

				if ($vuln_count > $this->page_size)
				{
					$result['vulnerabilities']  = array_slice($result['vulnerabilities'], 0, $this->page_size);
					$result['vuln_count']       = $this->page_size;
				}

				return array(
					'success'   => TRUE,
					'response'  => $result
				);
			}
			else
			{
				return array(
					'success'   => FALSE,
					'response'  => array(
						'message'   => 'get_internal_network_vulnerabilities() returned zero results'
					)
				);
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => $response['response']
			);
		}
	}

	// =====================
	// AttackSurface APIs
	// =====================

	public function get_attack_surface_assets($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/attack-surface/assets';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_attack_surface_assets_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/attack-surface/assets/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_attack_surface_vulnerabilities($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/attack-surface/vulnerabilities';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		// Optional CVE filter.
		if (isset($filter_params['cve']))
		{
			$query_params['CVE']        = $filter_params['cve'];
		}

		// Optional risks filter. Available options: Low, Medium, High, Critical.
		if (isset($filter_params['risks']) && is_array($filter_params['risks']))
		{
			$query_params['Risks']      = $filter_params['risks'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_attack_surface_vulnerabilities_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/attack-surface/vulnerabilities/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	// =====================
	// IdentitySecurity APIs
	// =====================

	public function get_identity_security_computers($client, $offset = 0, $limit = 100, $asset_name = NULL)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/computers';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional asset name filter.
		if (isset($asset_name))
		{
			$query_params['AssetName']  = $asset_name;
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_computers_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/computers/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_groups($client, $offset = 0, $limit = 100, $asset_name = NULL)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/groups';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional asset name filter.
		if (isset($asset_name))
		{
			$query_params['AssetName']  = $asset_name;
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_groups_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/groups/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_users($client, $offset = 0, $limit = 100, $asset_name = NULL)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/users';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional asset name filter.
		if (isset($asset_name))
		{
			$query_params['AssetName']  = $asset_name;
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_users_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/users/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_vulnerabilities($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/vulnerabilities';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		// Optional risks filter. Available options: Low, Medium, High, Critical.
		if (isset($filter_params['risks']) && is_array($filter_params['risks']))
		{
			$query_params['Risks']      = $filter_params['risks'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_identity_security_vulnerabilities_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/identity-security/vulnerabilities/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	// =====================
	// InternalNetwork APIs
	// =====================

	public function get_internal_network_assets($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/assets';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_internal_network_assets_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/assets/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_internal_network_configurations($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/configurations';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_internal_network_configurations_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/configurations/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_internal_network_vulnerabilities($client, $filter_params = NULL, $offset = 0, $limit = 100)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/vulnerabilities';
		$query_params       = ['Offset' => $offset, 'Limit' => $limit];

		// Optional IP address filter.
		if (isset($filter_params['ip_address']))
		{
			$query_params['IPAddress']  = $filter_params['ip_address'];
		}

		// Optional asset name filter.
		if (isset($filter_params['asset_name']))
		{
			$query_params['AssetName']  = $filter_params['asset_name'];
		}

		// Optional CVE filter.
		if (isset($filter_params['cve']))
		{
			$query_params['CVE']        = $filter_params['cve'];
		}

		// Optional risks filter. Available options: Low, Medium, High, Critical.
		if (isset($filter_params['risks']) && is_array($filter_params['risks']))
		{
			$query_params['Risks']      = $filter_params['risks'];
		}

		$query_str = http_build_query($query_params);

		$header_fields = array(
			'Accept: application/json',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_internal_network_vulnerabilities_csv($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/internal-network/vulnerabilities/export-csv';

		$header_fields = array(
			'Accept: text/plain',
			'x-subscription-id: '.$shield_cyber_info['subscription_id'],
			'x-api-key: '.$shield_cyber_info['api_key']
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	// =====================
	// Reporting APIs
	// =====================

	public function generate_report($client, $params)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/reporting/generate';

		$header_fields = array(
			'Content-Type: application/json',
			'Accept: application/json'
		);

		$post_fields = new stdClass();
		$post_fields->subscriptionId = $shield_cyber_info['subscription_id'];
		// ReportModules: AttackSurface, InternalNetwork, IdentitySecurity 
		$post_fields->modules[] = $params['modules'];
		// RiskSeverities: Low, Medium, High, Critical
		$post_fields->risks[] = $params['risks'];
		// ReportKinds: ExecutiveSummary, DetailedVulnerabilities, DetailedConfigurations, DetailedAssets
		$post_fields->kinds[] = $params['kinds'];
		$post_fields->formats[] = 'PDF';

		$response = $this->call_api('POST', $url, $header_fields, json_encode($post_fields));

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_report_download_link($client, $path)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/reporting/get-download-link';
		$query_str          = http_build_query(['path' => $path]);

		$header_fields = array(
			'Accept: text/plain'
		);

		$response = $this->call_api('GET', $url.'?'.$query_str, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => $response['result']
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	public function get_generated_reports_list($client)
	{
		$shield_cyber_info  = $this->redis_info($client);
		$url                = 'https://'.$shield_cyber_info['hostname'].'/external-api/v1/reporting/list';

		$header_fields = array(
			'Accept: application/json'
		);

		$response = $this->call_api('GET', $url, $header_fields);

		if ($response['result'] !== FALSE)
		{
			switch ($response['http_code'])
			{
				case 200:
					if ($response['size'])
					{
						return array(
							'success'   => TRUE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 400:
					if ($response['size'])
					{
						return array(
							'success'   => FALSE,
							'response'  => json_decode($response['result'], TRUE)
						);
					}
					break;
				case 401:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Unauthorized'
						)
					);
					break;
				case 403:
					return array(
						'success'   => FALSE,
						'response'  => array(
							'status'    => $response['http_code'],
							'message'   => 'Forbidden'
						)
					);
					break;
			}
		}
		else
		{
			return array(
				'success'   => FALSE,
				'response'  => array(
					'status'    => 'cURL returned false',
					'message'   => 'errno = '.$response['errno'].', error = '.$response['error']
				)
			);
		}
	}

	private function call_api($method, $url, $header_fields, $post_fields = NULL)
	{
		$this->ch = curl_init();

		switch ($method)
		{
			case 'POST':
				curl_setopt($this->ch, CURLOPT_POST, true);

				if (isset($post_fields))
				{
					curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post_fields);
				}

				break;
			case 'PUT':
				curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'PUT');

				if (isset($post_fields))
				{
					curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post_fields);
				}

				break;
			case 'DELETE':
				curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
				break;
		}

		if (is_array($header_fields))
		{
			curl_setopt($this->ch, CURLOPT_HTTPHEADER, $header_fields);
		}

		curl_setopt($this->ch, CURLOPT_URL, $url);
		curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
		//curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, false);
		//curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, false);

		curl_setopt($this->ch, CURLOPT_CONNECTTIMEOUT, 5);
		//curl_setopt($this->ch, CURLOPT_TIMEOUT, 10);

		if (($response['result'] = curl_exec($this->ch)) !== FALSE)
		{
			$response['size']       = curl_getinfo($this->ch, CURLINFO_SIZE_DOWNLOAD_T);
			$response['http_code']  = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
		}
		else
		{
			$response['errno'] 	= curl_errno($this->ch);
			$response['error'] 	= curl_error($this->ch);
		}

		curl_close($this->ch);

		return $response;
	}

	public function change_api_activation_status($client, $requested, $status)
	{
		$set_activation = ($status) ? 1 : 0;
		$check          = FALSE;

		#set soc redis keys
		$redis = new Redis();
		$redis->connect($this->redis_host, $this->redis_port, $this->redis_timeout);
		$redis->auth($this->redis_password);

		$check = $redis->hSet($client.'_information', 'shield_cyber_enabled', $set_activation);

		$redis->close();

		# set client redis keys
		if (is_int($check))
		{
			$status_data = array(
				'enabled'       => $set_activation,
				'request_sent'  => $set_activation,
				'request_user'  => $requested,
				'terms_agreed'  => $set_activation
			);

			$config_data = array(
				'shield_cyber_enabled' => $set_activation
			);

			if ($this->redis_info($client, NULL, 'SET', $status_data))
			{
				if ($this->client_config($client, NULL, 'SET', $config_data))
				{
					return TRUE;
				}
			}
		}

		return FALSE;
	}

	public function client_config($client, $field = NULL, $action = 'GET', $data = NULL)
	{
		$client_info    = client_redis_info($client);
		$client_key     = $client.'_configurations';

		$redis = new Redis();
		$redis->connect($client_info['redis_host'], $client_info['redis_port'], $this->redis_timeout);
		$redis->auth($client_info['redis_password']);

		if ($action === 'SET')
		{
			$check = $redis->hMSet($client_key, $data);
		}
		else
		{
			if (is_null($field))
			{
				$check = $redis->hGetAll($client_key);
			}
			else
			{
				$check = $redis->hGet($client_key, $field);
			}
		}   

		$redis->close();

		if (empty($check))
		{
			$check = NULL;
		}

		return $check;		
	}
}