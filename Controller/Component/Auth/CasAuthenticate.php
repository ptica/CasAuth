<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class CasAuthenticate extends BaseAuthenticate {

/**
 * Helper function to connect to the LDAP server
 * Looks at the plugin's settings to get the LDAP connection details
 * @throws CakeException
 * @return LDAP connection as per ldap_connect()
 */
	private function __ldapConnect() {
		$ldapConnection = @ldap_connect($this->settings['ldap_url']);

		if (!$ldapConnection) {
			throw new CakeException("Could not connect to LDAP authentication server");
		}

		return $ldapConnection;
	}

/**
 * Authentication hook to authenticate a user against an LDAP server.
 * @param CakeRequest $request The request that contains login information.
 * @param CakeResponse $response Unused response object.
 * @return mixed. False on login failure. An array of User data on success.
 */
	public function authenticate(CakeRequest $request, CakeResponse $response) {
		// This will probably be cn or an email field to search for
		/// $this->log("[LDAPAuthCake.authenticate] Authentication started", 'ldapauth');
		$fields = $this->settings['form_fields'];

		$userField = $fields['username'];

		$passField = $fields['password'];

		// Definitely not authenticated if we haven't got the request data...
		if (!isset($request->data[$this->settings['userModel']])) {
			///	$this->log("[LDAPAuthCake.authenticate] No request data, cannot authenticate", 'ldapauth');
			return false;
		}

		// We need to know the username, or email, or some other unique ID
		$submittedDetails = $request->data[$this->settings['userModel']];
		if (!isset($submittedDetails[$userField])) {
			///	$this->log("[LDAPAuthCake.authenticate] No username supplied, cannot authenticate", 'ldapauth');
			return false;
		}

		// Make sure it's a valid string...
		$username = $submittedDetails[$userField];
		if (!is_string($username)) {
			///	$this->log("[LDAPAuthCake.authenticate] Invalid username, cannot authenticate", 'ldapauth');
			return false;
		}

		// Make sure they gave us a password too...
		$password = $submittedDetails[$passField];
		if (!is_string($password) || empty($password)) {
			return false;
		}

		// Get the ldap_filter setting and insert the username
		$ldapFilter = $this->settings['ldap_filter'];

		$ldapFilter = preg_replace('/%USERNAME%/', $username, $ldapFilter);

		// We'll get the DN by default but we also want the useful bits we can map
		// to our own database details
		$attribs = array();

		foreach (array_keys($this->settings['ldap_to_user']) as $field) {
			$attribs = array_merge($attribs, preg_split('/\s+/', $field));
		}

		// Connect to LDAP server and search for the user object
		$ldapConnection = $this->__ldapConnect();

		// Suppress warning when no object found
		$results = @ldap_search($ldapConnection, $this->settings['ldap_base_dn'], $ldapFilter, $attribs, $attrsonly=0, $sizelimit=1);

		// Failed to find user details, not authenticated.
		if (!$results || ldap_count_entries($ldapConnection, $results) == 0) {
			///	$this->log("[LDAPAuthCake.authenticate] Could not find user $username", 'ldapauth');
			return false;
		}

		// Got multiple results, sysadmin did something wrong!
		if (ldap_count_entries($ldapConnection, $results) > 1) {
			///	$this->log("[LDAPAuthCake.authenticate] Multiple LDAP results for $username", 'ldapauth');
			return false;
		}

		// Found the user! Get their details
		$ldapUser = ldap_get_entries($ldapConnection, $results);

		$ldapUser = $ldapUser[0];

		$results = array();

		// Get a list of DB fields mapped to values from LDAP
		// NB fields can now be combined e.g. 'givenName sn', or we may take the supplied
		// value if the field is set to __SUPPLIED__ (for username field only).
		foreach ($this->settings['ldap_to_user'] as $ldapField => $dbField) {

			// First, if we're using __SUPPLIED__ username, then just use what they gave us
			if ($dbField == $userField && $ldapField == '__SUPPLIED__') {
				$results[$dbField] = $username;
			} else {
				// Split on whitespace and pull each field out in turn, then append
				$value = '';
				foreach (preg_split('/\s+/', $ldapField) as $ldapField) {
					$value .= $ldapUser[strtolower($ldapField)][0] . ' ';
				}

				$results[$dbField] = trim($value);
			}

			// If this is the unique username field, overwrite it for lookups.
			if ($dbField == $userField) {
				$username = strtolower($results[$dbField]);
			}
		}

		// Now try to re-bind as that user
		$bind = @ldap_bind($ldapConnection, $ldapUser['dn'], $password);

		// If the password didn't work, bomb out
		if (!$bind) {
			return false;
		}

		// Look up the user in our DB
		// look for ldap_lookup_field value in db_lookup_field
		$userModel = $this->settings['userModel'];
		list($plugin, $model) = pluginSplit($userModel);

		$conditions = array(
			$model . '.' . $this->settings['db_lookup_field'] => $results[$this->settings['ldap_lookup_field']],
		);

		$dbUser = ClassRegistry::init($userModel)->find('first', array(
			'conditions' => $conditions,
			'recursive'	=> false
		));

		// If we couldn't find them in the database, create a new DB entry
		if (empty($dbUser) || empty($dbUser[$model])) {
			///	$this->log("[LDAPAuthCake.authenticate] Could not find a database entry for $username", 'ldapauth');

			$results = array_merge($results, $this->settings['defaults']);
			if (!ClassRegistry::init($userModel)->save($results)) {
				///	echo "Failed to save new user\n"; print_r($results); print_r($username);
				return false;
			}

			$id = ClassRegistry::init($userModel)->getLastInsertID();
			$dbUser = ClassRegistry::init($userModel)->findById($id);
		}

		// Ensure there's nothing in the password field
		unset($dbUser[$model][$fields['password']]);

		// ...and return the user object.
		return $dbUser[$model];
	}

	// TODO split functionality to common methods of BaseAuthenticate
	// ie.
	// protected function _findUser($conditions, $password = null) {
	// protected function _checkFields(CakeRequest $request, $model, $fields) {
	
}
