<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Shield_cyber extends CI_Controller
{
	public function __construct()
	{
		parent::__construct();

		if (!$this->tank_auth->is_logged_in()) 
		{	
			if ($this->input->is_ajax_request()) 
			{
				redirect('/auth/ajax_logged_out_response');
			} 
			else 
			{
				redirect('/auth/login');
			}
		}

		$this->utility->restricted_access();

		$this->load->model('account/account_model', 'account');
		$this->load->library('shield_cyber_api');
	}

	function _remap($method, $args)
	{ 
		if (method_exists($this, $method))
		{
			$this->$method($args);
		}
		else
		{
			$this->index($method, $args);
		}
	}

	public function index($method, $args = array())
	{
		$asset = client_redis_info_by_code();

		# Page Data	
		$nav['client_name']         = $asset['client'];
		$nav['client_code']         = $asset['code'];

		$data['client_code']        = $asset['code'];
		$data['sub_navigation']     = $this->load->view('customer-management/navigation', $nav, TRUE);	
		$data['shield_cyber_info']  = $this->shield_cyber_api->redis_info($asset['seed_name']);
		$data['show_activation']    = FALSE;
		$data['api_tested']         = FALSE;
		$data['request_was_sent']   = FALSE;
		$data['api_enabled']        = FALSE;
		$data['action']             = 'create';

		if (!is_null($data['shield_cyber_info']))
		{
			$data['action'] = 'modify';

			if (intval($data['shield_cyber_info']['tested']))
			{
				$data['show_activation']    = TRUE;
				$data['api_tested']         = TRUE;

				if (intval($data['shield_cyber_info']['request_sent']))
				{
					$data['request_was_sent'] = TRUE;
				}

				if (intval($data['shield_cyber_info']['enabled']))
				{
					$data['api_enabled'] = TRUE;
				}
			}
		}

		# Page Views
		$this->load->view('assets/header');	
		$this->load->view('customer-management/shield_cyber/start', $data);
		$this->load->view('assets/footer');
	}

	public function create()
	{
		$asset = client_redis_info_by_code();

		if ($this->input->method(TRUE) === 'POST')
		{
			$this->form_validation->set_rules('hostname', 'Hostname', 'trim|required|callback_host_ip_check');
			$this->form_validation->set_rules('subscription_id', 'Subscription ID', 'trim|required');
			$this->form_validation->set_rules('api_key', 'API Key', 'trim|required');

			if ($this->form_validation->run()) 
			{
				$redis_data = array(
					'hostname'          => $this->input->post('hostname'),
					'subscription_id'   => $this->input->post('subscription_id'),
					'api_key'           => $this->input->post('api_key')
				);

				if ($this->shield_cyber_api->create_shield_cyber_redis_key($asset['seed_name'], $redis_data))
				{
					# Write To Logs
					$log_message = '[Shield Cyber API Created] user: '.$this->session->userdata('username').' | for client: '.$asset['client'];
					$this->utility->write_log_entry('info', $log_message);

					# Success
					$this->session->set_userdata('my_flash_message_type', 'success');
					$this->session->set_userdata('my_flash_message', '<p>Shield Cyber API settings were successfully created.</p>');

					redirect('/customer-management/shield_cyber/'.$asset['code']);
				}
				else
				{
					# Something went wrong
					$this->session->set_userdata('my_flash_message_type', 'error');
					$this->session->set_userdata('my_flash_message', '<p>Something went wrong. Please try again.</p>');
				}
			}
			else
			{
				if (validation_errors()) 
				{
					$this->session->set_userdata('my_flash_message_type', 'error');
					$this->session->set_userdata('my_flash_message', validation_errors());
				}
			}
		}

		# Page Data
		$data['client_code'] = $asset['code'];

		# Page Views
		$this->load->view('assets/header');
		$this->load->view('customer-management/shield_cyber/create', $data);
		$this->load->view('assets/footer');
	}

	public function modify()
	{
		$asset = client_redis_info_by_code();

		if ($this->input->method(TRUE) === 'POST')
		{
			$this->form_validation->set_rules('hostname', 'Hostname', 'trim|required|callback_host_ip_check');
			$this->form_validation->set_rules('subscription_id', 'Subscription ID', 'trim|required');
			$this->form_validation->set_rules('api_key', 'API Key', 'trim|required');

			if ($this->form_validation->run())
			{
				$redis_data = array(
					'hostname'          => $this->input->post('hostname'),
					'subscription_id'   => $this->input->post('subscription_id'),
					'api_key'           => $this->input->post('api_key')
				);

				if ($this->shield_cyber_api->create_shield_cyber_redis_key($asset['seed_name'], $redis_data))
				{
					# Write To Logs
					$log_message = '[Shield Cyber API Modified] user: '.$this->session->userdata('username').' | for client: '.$asset['client'];
					$this->utility->write_log_entry('info', $log_message);

					# Success
					$this->session->set_userdata('my_flash_message_type', 'success');
					$this->session->set_userdata('my_flash_message', '<p>Shield Cyber API settings were successfully updated.</p>');

					redirect('/customer-management/shield_cyber/'.$asset['code']);
				}
				else
				{
					# Something went wrong
					$this->session->set_userdata('my_flash_message_type', 'error');
					$this->session->set_userdata('my_flash_message', '<p>Something went wrong. Please try again.</p>');
				}
			}
			else
			{
				if (validation_errors()) 
				{
					$this->session->set_userdata('my_flash_message_type', 'error');
					$this->session->set_userdata('my_flash_message', validation_errors());
				}
			}
		}

		# Page Data
		$data['client_code']        = $asset['code'];
		$data['shield_cyber_info']  = $this->shield_cyber_api->redis_info($asset['seed_name']);

		# Page Views
		$this->load->view('assets/header');
		$this->load->view('customer-management/shield_cyber/modify', $data);
		$this->load->view('assets/footer');
	}

	public function api_test()
	{
		$asset      = client_redis_info_by_code();
		$response   = $this->shield_cyber_api->get_internal_network_assets($asset['seed_name']);

		if ($response['success'])
		{
			$assets         = [];
			$asset_count    = count($response['response']);

			if ($asset_count)
			{
				$this->shield_cyber_api->redis_info($asset['seed_name'], NULL, 'SET', array('tested' => '1'));
			}

			foreach ($response['response'] as $asset)
			{
				$assets[] = array(
					'asset_name'    => !empty($asset['assetName']) ? $asset['assetName'] : 'N/A',
					'ip_address'    => !empty($asset['ipAddress']) ? $asset['ipAddress'] : 'N/A',
					// 'os'                => !empty($asset['operatingSystem']) ? $asset['operatingSystem'] : 'N/A',
					'criticality'   => !empty($asset['criticality']) ? $asset['criticality'] : false,
					'group_names'   => !empty($asset['groupNames']) ? $asset['groupNames'] : false,
					// 'max_criticality'   => !empty($asset['maxCriticality']) ? $asset['maxCriticality'] : 'N/A'
				);
			}

			$return_array = array(
				'success'       => TRUE,
				'response'      => $response['response'],
				'results'       => $assets,
				'result_count'  => $asset_count
			);
		}
		else
		{
			$return_array = array(
				'success'   => FALSE,
				'response'  => $response['response']
			);
		}

		echo json_encode($return_array);
	}

	public function activate()
	{
		$asset = client_redis_info_by_code();

		$shield_cyber_info              = $this->shield_cyber_api->redis_info($asset['seed_name']);
		$data['authorized_to_modify']   = $this->account->get_authorized_to_modify($asset['id']);
		$data['client_code']            = $asset['code'];
		$data['client_title']           = $asset['client'];
		$data['requested']              = $shield_cyber_info['request_sent'];
		$data['request_user']           = $shield_cyber_info['request_user'] ?? NULL;
		$data['terms_agreed']           = intval($shield_cyber_info['terms_agreed']);

		$this->load->view('customer-management/shield_cyber/activate', $data);
	}

	public function do_activate()
	{
		$asset = client_redis_info_by_code();

		$this->form_validation->set_rules('requesting_user', 'Requesting Contact', 'trim|required');
		$this->form_validation->set_rules('api-terms-of-agreement', 'api-terms-of-agreement', 'trim|required');

		if ($this->form_validation->run()) 
		{
			$requested_by   = $this->input->post('requesting_user');			
			$requested_user = $this->account->get_user_by_code($requested_by);
			$requested_name = $requested_user->first_name.' '.$requested_user->last_name;

			if ($this->shield_cyber_api->change_api_activation_status($asset['seed_name'], $requested_by, TRUE))
			{
				$this->account->send_api_activation_notification($asset['id'], 'shield_cyber', $requested_name);

				# Write To Logs
				$log_message = '[Shield Cyber API Enabled] user: '.$this->session->userdata('username').', has enabled api for customer: '.$asset['client'].', per the request of '.$requested_name;
				$this->utility->write_log_entry('info', $log_message);

				# Set Success Alert Response
				$this->session->set_userdata('my_flash_message_type', 'success');
				$this->session->set_userdata('my_flash_message', '<p>The Shield Cyber API for: <strong>'.$asset['client'].'</strong>, has been successfully enabled.</p>');

				$response = array(
					'success'   => true,
					'goto_url'  => '/customer-management/shield_cyber/'.$asset['code']
				);
				echo json_encode($response);
			}
			else
			{
				# Set Error
				$response = array(
					'success'   => false,
					'message'   => '<p>Something went wrong. Please try again.</p>'
				);
				echo json_encode($response);
			}
		}
		else
		{
			if (validation_errors()) 
			{
				# Set Error
				$response = array(
					'success'   => false,
					'message'   => validation_errors()
				);
				echo json_encode($response);
			}
		}
	}

	public function disable()
	{
		$asset = client_redis_info_by_code();

		$data['authorized_to_modify']   = $this->account->get_authorized_to_modify($asset['id']);
		$data['client_code']            = $asset['code'];
		$data['client_title']           = $asset['client'];

		$this->load->view('customer-management/shield_cyber/disable', $data);
	}

	public function do_disable()
	{
		$asset = client_redis_info_by_code();

		$this->form_validation->set_rules('requesting_user', 'Requesting Contact', 'trim|required');
		$this->form_validation->set_rules('api-terms-of-agreement', 'api-terms-of-agreement', 'trim|required');

		if ($this->form_validation->run()) 
		{
			$requested_by   = $this->input->post('requesting_user');			
			$requested_user = $this->account->get_user_by_code($requested_by);
			$requested_name = $requested_user->first_name.' '.$requested_user->last_name;

			if ($this->shield_cyber_api->change_api_activation_status($asset['seed_name'], $requested_by, FALSE))
			{
				$this->account->send_api_disabled_notification($asset['id'], 'shield_cyber', $requested_name);

				# Write To Logs
				$log_message = '[Shield Cyber API Disabled] user: '.$this->session->userdata('username').', has disabled api for customer: '.$asset['client'].', per the request of '.$requested_name;
				$this->utility->write_log_entry('info', $log_message);

				# Set Success Alert Response
				$this->session->set_userdata('my_flash_message_type', 'success');
				$this->session->set_userdata('my_flash_message', '<p>The Shield Cyber API for: <strong>'.$asset['client'].'</strong>, has been successfully disabled.</p>');

				$response = array(
					'success'   => true,
					'goto_url'  => '/customer-management/shield_cyber/'.$asset['code']
				);
				echo json_encode($response);
			}
			else
			{
				# Set Error
				$response = array(
					'success'   => false,
					'message'   => '<p>Something went wrong. Please try again.</p>'
				);
				echo json_encode($response);
			}
		}
		else
		{
			if (validation_errors()) 
			{
				# Set Error
				$response = array(
					'success'   => false,
					'message'   => validation_errors()
				);
				echo json_encode($response);
			}
		}
	}

	public function host_ip_check($value)
	{
		if (strlen($value) === 0)
		{
			$this->form_validation->set_message('host_ip_check', 'The {field} field is required.');
			return FALSE;
		}

		$dot_count      = substr_count($value, '.');
		$colon_count    = substr_count($value, ':');

		if ($dot_count === 0 && $colon_count === 0)
		{
			if (strcmp($value, 'localhost') !== 0)
			{
				$this->form_validation->set_message('host_ip_check', 'The {field} field must contain a valid host or IP address.');
				return FALSE;
			}
		}
		else if ($colon_count > 0)
		{
			$rv = preg_match('/^\[([^\]]+)\]$/', $value, $matches);

			if ($rv === 0 || $rv === FALSE)
			{
				$this->form_validation->set_message('host_ip_check', '{field} - IPv6 addresses must be written within [brackets].');
				return FALSE;
			}
			else
			{
				if (filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === FALSE)
				{
					$this->form_validation->set_message('host_ip_check', '{field} - invalid IPv6 address format.');
					return FALSE;
				}
			}
		}
		else if ($dot_count > 0)
		{
			switch ($dot_count)
			{
				case 3:
					if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE)
					{
						return TRUE;
					}
				default:
					$rv = preg_match('/^(?=.{1,255}$)(((?!-)[a-z0-9-]{1,63}(?<!-)\.){1,127}[a-z]{2,63})$/i', $value, $matches);

					if ($rv === 0 || $rv === FALSE)
					{
						$this->form_validation->set_message('host_ip_check', 'The {field} field must contain a valid host or IP address.');
						return FALSE;
					}
			}
		}

		return TRUE;
	}
}