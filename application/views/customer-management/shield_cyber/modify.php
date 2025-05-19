<?php defined('BASEPATH') OR exit('No direct script access allowed'); ?>
<div class="row">
	<div class="col-md-12">		
		<ol class="breadcrumb">
			<li><a href="/customer-management">Customer Management</a></li>
			<li><a href="/customer-management/customer/<?php echo $client_code; ?>">Customer Overview</a></li>
			<li><a href="/customer-management/shield-cyber/<?php echo $client_code; ?>">Shield Cyber API</a></li>
			<li class="active">Modify</li>
		</ol>	
	</div>
</div>
<div class="row">
	<div class="col-md-8">		
		<div class="panel panel-light">
			<div class="panel-heading">
				<div class="clearfix">
					<div class="pull-left">
						<h3>Shield Cyber API Integration</h3>
						<h4>Modify</h4>
					</div>
					<div class="pull-right">
						<a href="/customer-management/shield-cyber/<?php echo $client_code; ?>" type="button" class="btn btn-default">Cancel &amp; Return</a>
					</div>
				</div>
			</div>			
			<?php echo form_open($this->uri->uri_string(), array('autocomplete' => 'off', 'aria-autocomplete' => 'off')); ?>
				<div class="panel-body">
					<div class="row">
						<div class="col-md-12">
							<div class="form-group<?php echo form_error('hostname') ? ' has-error':''; ?>">
								<label class="control-label" for="hostname">Hostname</label>
								<div class="input-group">
									<div class="input-group-addon">https://</div>
									<input type="text" class="form-control" id="hostname" name="hostname" placeholder="api.shieldcyber.io" value="<?php echo set_value('hostname', $shield_cyber_info['hostname']); ?>">
								</div>
							</div>
							<div class="form-group<?php echo form_error('subscription_id') ? ' has-error':''; ?>">
								<label class="control-label" for="subscription_id">Subscription ID <span class="help-block inline small">( The Subscription ID can be found on the My Account page under the Subscriptions tab. )</span></label>
								<input type="text" class="form-control" id="subscription_id" name="subscription_id" placeholder="Enter Subscription ID" value="<?php echo set_value('subscription_id', $shield_cyber_info['subscription_id']); ?>">
							</div>
							<div class="form-group<?php echo form_error('api_key') ? ' has-error':''; ?>">
								<label class="control-label" for="api_key">API Key <span class="help-block inline small">( The API Key linked to a subscription can be found on the My Account page under the Subscriptions tab. )</span></label>
								<input type="text" class="form-control" id="api_key" name="api_key" placeholder="Enter API Key" value="<?php echo set_value('api_key', $shield_cyber_info['api_key']); ?>">
							</div>
						</div>
					</div>
					<div class="row">
						<div class="col-md-12 text-right">
							<button type="submit" class="btn btn-success" data-loading-text="Updating...">Update</button>
						</div>
					</div>
				</div>
			<?php echo form_close(); ?>			
		</div>		
	</div>
</div>