<?php

/**
 * Easy Reddit API Wrapper
 * for accessing the Reddit API
 * requires php >= 5.4.0
 *
 * Usage:
 *   $reddit = Reddit::App($client_id, $client_secret, $redirect_uri, $user_agent);
 *   $reddit->login($username, $password);
 *   $user = $reddit->getCurrentUser();
 *
 * @link https://github.com/reddit/reddit/wiki/
 * @link https://www.reddit.com/dev/api
 */
class Reddit {
	const ENDPOINT_OAUTH = "https://oauth.reddit.com";
	const ENDPOINT_OAUTH_AUTHORIZE = "https://www.reddit.com/api/v1/authorize";
	const ENDPOINT_OAUTH_TOKEN = "https://www.reddit.com/api/v1/access_token";
	const ENDPOINT_OAUTH_REVOKE = "https://www.reddit.com/api/v1/revoke_token";

	public static $scopes = [ "creddits", "modcontributors", "modconfig", "subscribe", "wikiread", "wikiedit", "vote",
							  "mysubreddits", "submit", "modlog", "modposts", "modflair", "save", "modothers", "read",
							  "privatemessages", "report", "identity", "livemanage", "account", "modtraffic", "edit",
							  "modwiki", "modself", "history", "flair" ];

	private $client_id;
	private $client_secret;
	private $scope;
	private $access_token;
	private $expire_timestamp;
	private $refresh_token;
	private $token_type;
	private $authorized_timestamp;
	private $remember;
	private $user_agent;
	private $last_transfer_info;

	/**
	 * Class Constructor
	 *
	 * @link https://github.com/reddit/reddit/wiki/
	 * @link https://www.reddit.com/dev/api
	 * @param string $client_id
	 * @param string $client_secret
	 * @param string $redirect_uri
	 * @param string $user_agent eg. "webapp:{APPNAME}:v1.0 (by /u/{USERNAME})"
	 */
	public function __construct($client_id, $client_secret, $redirect_uri = "", $user_agent = "") {
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->redirect_endpoint = $redirect_uri;
		$this->user_agent = $user_agent;
	}

	/**
	 * App
	 *
	 * Class constructor alias
	 *
	 * @link https://github.com/reddit/reddit/wiki/
	 * @link https://www.reddit.com/dev/api
	 * @param string $client_id
	 * @param string $client_secret
	 * @param string $redirect_uri
     * @param string $user_agent eg. "webapp:{APPNAME}:v1.0 (by /u/{USERNAME})"
	 * @return Reddit instance
	 */
	public static function App($client_id, $client_secret, $redirect_uri = "", $user_agent = "") {
		return new Reddit($client_id, $client_secret, $redirect_uri, $user_agent);
	}

	/**
	 * Login
	 *
	 * Authenticates user by password
	 *
	 * @param $username
	 * @param $password
	 * @param bool|int $remember Number of seconds to remember user (uses cookies), false if not at all (default).
	 * @return Reddit instance or false if authorization fail
	 * @throws InvalidArgumentException
	 */
	public function login($username, $password, $remember = false) {
		if (!is_string($username) || !is_string($password))
			throw new InvalidArgumentException("\$username & \$password parameters in login method must be of type string.");
		elseif ($remember !== false && !is_numeric($remember))
			throw new InvalidArgumentException("\$remember parameter in login method must be numeric or false.");

		$this->scope = join(",", Reddit::$scopes);
		$this->remember = $remember;

		if ($this->isAuthorized() && $username == $this->getCurrentUser()->name)
			return $this;

		$postData = [
			"grant_type" => "password",
			"username" => $username,
			"password" => $password,
		];

		$token = self::runCurl(self::ENDPOINT_OAUTH_TOKEN, $postData, true);

		if (isset($token->access_token)) {
			$this->authorized_timestamp = time();
			$this->access_token = $token->access_token;
			$this->token_type = $token->token_type;
			$this->expire_timestamp = $token->expires_in;
			$this->refresh_token = @$token->refresh_token;

			if ($this->remember !== false)
				$this->saveToken();

			return $this;
		}

		return false;
	}

	/**
	 * Authorize
	 *
	 * Authorizes user by link
	 *
	 * @param string|array $scopes Available scopes can be found in Reddit::scopes. Pass "*" to use all.
	 * @param bool $redirect Redirect to authorization url
	 * @param bool|int $remember Number of seconds to remember user (uses cookies), false if not at all (default).
	 * @param bool $force Force new authorization
	 * @return Reddit instance or false if authorization fail
	 * @throws Exception|InvalidArgumentException
	 */
	public function authorize($scopes = "*", $redirect = true, $remember = false, $force = false) {
		if (!$this->redirect_endpoint)
			throw new Exception("Invalid redirect URI");
		elseif (!is_bool($redirect) || !is_bool($force))
			throw new InvalidArgumentException("\$redirect & \$force parameters in authorize method must be of type boolean.");
		elseif ($remember !== false && !is_numeric($remember))
			throw new InvalidArgumentException("\$remember parameter in authorize method must be numeric or false.");

		if ($scopes == "*")
			$scopes = Reddit::$scopes;

		if (!$this->validateScope($scopes))
			throw new Exception("Invalid scope");
		elseif (is_string($scopes))
			$this->scope = $scopes;
		elseif (is_array($scopes))
			$this->scope = join(",", $scopes);
		else
			throw new Exception("\$scopes parameter in authorize method must be of type string or array.\"");

		$this->remember = $remember;

		if ($this->isAuthorized() && !$force)
			return $this;

		if (isset($_GET["code"])) {
			$code = $_GET["code"];

			$postData = [
				"code" => $code,
				"redirect_uri" => $this->redirect_endpoint,
				"grant_type" => "authorization_code",
			];

			$token = self::runCurl(self::ENDPOINT_OAUTH_TOKEN, $postData, true);

			if (isset($token->access_token)) {
				$this->authorized_timestamp = time();
				$this->access_token = $token->access_token;
				$this->token_type = $token->token_type;
				$this->expire_timestamp = $token->expires_in;
				$this->refresh_token = @$token->refresh_token;

				if (is_numeric($this->remember))
					$this->saveToken();

				return $this;
			}
		}

		if ($redirect)
			header("Location: {$this->getAuthURL()}");

		return false;
	}

	/**
	 * Unauthorize
	 *
	 * revokeToken alias
	 *
	 * @return object|bool cURL Response
	 */
	public function unAuthorize() {
		return $this->revokeToken();
	}

	/**
	 * Logout
	 *
	 * revokeToken alias
	 *
	 * @return object|bool cURL Response
	 */
	public function logout() {
		return $this->revokeToken();
	}

	/**
	 * Is Authorized
	 *
	 * Checks if reddit token is set
	 *
	 * @return bool
	 */
	public function isAuthorized() {
		$token = $this->getToken();

		if (!$token)
			return false;

		if (isset($token["refresh_token"]) && ($token["time_authorized"] + $token["expires_in"]) < time()) {
			// Will refresh token if expired, but not update cookie expiration date
			$this->refreshToken(false);
		}

		return true;
	}

	/**
	 * Get Authorization URL
	 *
	 * Gets authorization url
	 *
	 * @return string
	 */
	public function getAuthURL() {
		return sprintf("%s?duration=%s&response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			self::ENDPOINT_OAUTH_AUTHORIZE,
			(bool)$this->remember && $this->remember >= 3600 ? "permanent" : "temporary",
			$this->client_id,
			$this->redirect_endpoint,
			$this->scope,
			rand());
	}

	/**
	 * Add Comment
	 *
	 * Submits a new comment or reply to a message
	 *
	 * @scope Based on thing. If thing is x then scope must be y:
	 *      link or comment: submit
	 *      message: privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_comment
	 * @param string $thing_id The full name of parent thing
	 * @param string $text Raw markdown text
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function addComment($thing_id, $text) {
		if (!is_string($thing_id) || !is_string($text))
			throw new InvalidArgumentException("addComment method only accepts strings.");

		$url = sprintf("%s/api/comment", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"thing_id" => $thing_id,
			"text"     => $text,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Needs CAPTCHA
	 *
	 * Checks whether CAPTCHAs are needed for API endpoints
	 *
	 * @scope any
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_needs_captcha
	 * @return object|bool cURL Response
	 */
	public function needsCaptcha() {
		$url = sprintf("%s/api/needs_captcha", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * New CAPTCHA
	 *
	 * Gets the iden of a new CAPTCHA, if the user cannot read the current one
	 *
	 * @scope any
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_new_captcha
	 * @return object|bool cURL Response
	 */
	public function newCaptcha() {
		$url = sprintf("%s/api/new_captcha", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json"
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get CAPTCHA Image
	 *
	 * Fetches a new CAPTCHA image from a given iden value
	 *
	 * @scope any
	 * @link http://www.reddit.com/dev/api/oauth#GET_captcha_{iden}
	 * @param string $iden The iden value of a new CAPTCHA from getNewCaptcha method
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getCaptchaImg($iden) {
		if (!is_string($iden))
			throw new InvalidArgumentException("getCaptchaImg method only accepts strings.");

		$url = sprintf("%s/captcha/{$iden}", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Give Gold
	 *
	 * Spends reddit gold creddits on giving gold to other users
	 *
	 * @scope creddits
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_v1_gold_gild_{fullname}
	 * @param string $name Valid existing username or fullname of thing. Must provide $months if username
	 * @param int $months Integer between 1 and 36
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function giveGold($name, $months = null) {
		if (!is_string($name))
			throw new InvalidArgumentException("\$name parameter in giveGold method only accepts string.");

		if (is_int($months)) {
			$url = sprintf("%s/api/v1/gold/give/username", self::ENDPOINT_OAUTH);
			$postData = [
				"username" => $name,
				"months" => $months,
			];
		} else {
			$url = sprintf("%s/api/v1/gold/gild/fullname", self::ENDPOINT_OAUTH);
			$postData = [
				"fullname" => $name,
			];
		}

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Content
	 *
	 * Deletes a given link or comment created by the user
	 *
	 * @scope edit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_del
	 * @param string $id The fullname of the link or comment to delete (e.g. t3_1kuinv for link, t1_1kuinv for comment).
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteContent($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("deleteContent method only accepts strings.");

		$url = sprintf("%s/api/del", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Edit Content
	 *
	 * Edits the content of a self post or comment created by the user
	 *
	 * @scope edit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_editusertext
	 * @param string $id The fullname of the link or comment to delete (e.g. t3_1kuinv for link, t1_1kuinv for comment).
	 * @param string $text The raw markdown text to replace the content with.
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function editContent($id, $text) {
		if (!is_string($id) || !is_string($text))
			throw new InvalidArgumentException("editContent method only accepts strings.");

		$url = sprintf("%s/api/editusertext", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"thing_id" => $id,
			"text" => $text,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Update
	 *
	 * Deletes an update from the thread
	 *
	 * @scope edit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_delete_update
	 * @param string $id The ID of a single update. e.g. LiveUpdate_ff87068e-a126-11e3-9f93-12313b0b3603
	 * @param string $thread
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteUpdate($id, $thread) {
		if (!is_string($id) || !is_string($thread))
			throw new InvalidArgumentException("deleteUpdate method only accepts strings.");

		$url = sprintf("%s/api/live/{$thread}/delete_update", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Strike Update
	 *
	 * Strikes (marks incorrect and crosses out) the content of an update
	 *
	 * @scope edit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_strike_update
	 * @param string $id The ID of a single update. e.g. LiveUpdate_ff87068e-a126-11e3-9f93-12313b0b3603
	 * @param string $thread
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function strikeUpdate($id, $thread) {
		if (!is_string($id) || !is_string($thread))
			throw new InvalidArgumentException("strikeUpdate method only accepts strings.");

		$url = sprintf("%s/api/live/{$thread}/strike_update", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Send Replies
	 *
	 * Enables or disables inbox replies for a link or comment
	 *
	 * @scope edit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_sendreplies
	 * @param string $id The fullename of a thing created by the user
	 * @param bool $state Enable/disable
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function sendReplies($id, $state) {
		if (!is_string($id))
			throw new InvalidArgumentException("\$id parameter in sendReplies method only accepts string.");
		elseif (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in sendReplies method only accepts boolean.");

		$url = sprintf("%s/api/sendreplies", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $id,
			"state" => $state,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get User Flairs
	 *
	 * Recieves current or specific users flair options
	 *
	 * @scope flair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flairselector
	 * @param string $subreddit
	 * @param string $name Available to subreddit moderators. Will return flair options for $name if specified.
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getUserFlairs($subreddit, $name = null) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("getUserFlairs method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/flairselector", self::ENDPOINT_OAUTH);

		if ($name)
			$postData = ["name" => $name];
		else
			$postData = null;

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Link Flairs
	 *
	 * Recieves link flair options
	 *
	 * @scope flair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flairselector
	 * @param string $subreddit
	 * @param string $link The fullename of a link
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getLinkFlairs($subreddit, $link) {
		if (!is_string($subreddit) || !is_string($link))
			throw new InvalidArgumentException("getLinkFlairs method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/flairselector", self::ENDPOINT_OAUTH);
		$postData = [
			"link" => $link,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set User Flairs
	 *
	 * Sets current or specific users flair
	 *
	 * @scope flair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_selectflair
	 * @param string $subreddit
	 * @param string $template_id
	 * @param string $text
	 * @param string $name Available to subreddit moderators. Will return flair options for $name if specified.
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setUserFlair($subreddit, $template_id, $text, $name = null) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("setUserFlair method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/selectflair", self::ENDPOINT_OAUTH);

		if ($name)
			$postData = [
				"api_type" => "json",
				"flair_template_id" => $template_id,
				"name" => $name,
				"text" => $text,
			];
		else
			$postData = null;

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Link Flair
	 *
	 * @scope flair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_selectflair
	 * @param string $subreddit
	 * @param string $link The fullename of a link
	 * @param string $template_id
	 * @param string $text No longer than 64 characters
	 * @return bool|object cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setLinkFlair($subreddit, $link, $template_id, $text) {
		if (!is_string($subreddit) || !is_string($link) || !is_string($text))
			throw new InvalidArgumentException("setLinkFlair method only accepts strings.");
		elseif (strlen($text) > 64)
			throw new InvalidArgumentException("\$text parameter in setLinkFlair method must not be longer than 64 characters.");

		$url = sprintf("%s/r/{$subreddit}/api/selectflair", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"flair_template_id" => $template_id,
			"link" => $link,
			"text" => $text,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Flair Enabled
	 *
	 * @scope flair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_setflairenabled
	 * @param string $subreddit
	 * @param bool $state
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setFlairEnabled($subreddit, $state) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter in setFlairEnabled method only accepts string.");
		elseif (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in setLinkFlair method only accepts boolean.");

		$url = sprintf("%s/r/{$subreddit}/api/selectflair", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"flair_enabled" => $state,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Current User History
	 *
	 * Gets the historical data of a user
	 *
	 * @scope history
	 * @link http://www.reddit.com/dev/api/oauth#scope_history
	 * @param string $username The desired user. Must be already authenticated
	 * @param string $where The data to retrieve. One of overview, submitted, comments, liked, disliked, hidden, saved, gilded
	 * @param string $sort Sort data. One of hot, new, top, controversial
	 * @param string $time Filter by time. One of hour, day, week, month, year, all
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getCurrentUserHistory($username, $where, $sort = "new", $time = "all") {
		if (!is_string($username) || !is_string($where) || !is_string($sort) || !is_string($time))
			throw new InvalidArgumentException("getHistory method only accepts strings.");
		elseif (!in_array($sort, ["hot", "new", "top", "controversial"]))
			throw new InvalidArgumentException("\$sort parameter in getCurrentUserHistory method must be one of hot, new, top, controversial.");
		elseif (!in_array($time, ["hour", "day", "week", "month", "year", "all"]))
			throw new InvalidArgumentException("\$time parameter in getCurrentUserHistory method must be one of hour, day, week, month, year, all.");

		$url = sprintf("%s/user/{$username}/{$where}?sort={$sort}&t={$time}", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Current User
	 *
	 * Gets data for the current user
	 *
	 * @scope identity
	 * @link http://www.reddit.com/dev/api#GET_api_v1_me
	 * @return object|bool cURL Response
	 */
	public function getCurrentUser() {
		$url = sprintf("%s/api/v1/me", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Current User Preferences
	 *
	 * Gets preference data for the current user based on fields provided
	 *
	 * @scope identity
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_prefs
	 * @param array $fields List of pref data to return. Full list at @link
	 * @return object|bool cURL Response
	 */
	public function getCurrentUserPrefs(array $fields) {
		$url = sprintf("%s/api/v1/me/prefs?fields=%s", self::ENDPOINT_OAUTH, join(",", $fields));

		return self::runCurl($url);
	}

	/**
	 * Get Current User Trophies
	 *
	 * Gets current user trophies
	 *
	 * @scope identity
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_trophies
	 * @return object|bool cURL Response
	 */
	public function getCurrentUserTrophies() {
		$url = sprintf("%s/api/v1/me/trophies", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Accept Live Thread Contributor Invite
	 *
	 * Accepts a pending invitation to contribute to a live thread
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_accept_contributor_invite
	 * @param string $thread
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function acceptLiveThreadContributorInvite($thread) {
		if (!is_string($thread))
			throw new InvalidArgumentException("\$thread parameter in acceptLiveThreadContributorInvite method only accepts string.");

		$url = sprintf("%s/api/live/{$thread}/accept_contributor_invite", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Close Live Thread
	 *
	 * Permanently closes a thread, disallowing future updates
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_close_thread
	 * @param string $thread
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function closeLiveThread($thread) {
		if (!is_string($thread))
			throw new InvalidArgumentException("\$thread parameter in closeLiveThread method only accepts string.");

		$url = sprintf("%s/api/live/{$thread}/close_thread", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Edit Live Thread
	 *
	 * Configures a live thread
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_close_thread
	 * @param string $thread
	 * @param array $settings allowed keys: description (string), nsfw (bool), resources (string), title (string <= 120 char)
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function editLiveThread($thread, array $settings) {
		$settings_cond = ["description" => "string", "nsfw" => "boolean", "resources" => "string", "title" => "string"];

		if (!is_string($thread))
			throw new InvalidArgumentException("\$thread parameter in editLiveThread method only accepts string.");
		elseif ($key_diff = array_diff_key($settings, $settings_cond))
			throw new InvalidArgumentException("Invalid \$settings key(s) provided: " . join(", ", $key_diff));
		elseif ($type_diff = array_diff_assoc(array_map("gettype", $settings), $settings_cond)) {
			$invalid_types = array_map(function ($k, $v) { return "$k=$v"; }, array_keys($type_diff), array_values($type_diff));
			throw new InvalidArgumentException("Invalid \$settings value type(s) provided: " . join(", ", $invalid_types));
		} elseif (isset($settings["title"]) && strlen($settings["title"]) > 120)
			throw new InvalidArgumentException("\$settings['title'] parameter in editLiveThread method must not be longer than 120 characters.");

		$url = sprintf("%s/api/live/{$thread}/edit", self::ENDPOINT_OAUTH);
		$postData = array_merge([
			"api_type" => "json",
		], $settings);

		return self::runCurl($url, $postData);
	}

	/**
	 * Invite Contributor To Live Thread
	 *
	 * Invites another user to contribute to the thread
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_invite_contributor
	 * @param string $thread
	 * @param string $name Name of an existing user
	 * @param string $permissions Permission description e.g. +update,+edit,-manage
	 * @param string $type One of liveupdate_contributor_invite, liveupdate_contributor
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function inviteContributorToLiveThread($thread, $name, $permissions, $type) {
		if (!is_string($thread) || !is_string($name) || !is_string($permissions) || !is_string($type))
			throw new InvalidArgumentException("Parameters in inviteContributorToLiveThread method only accepts strings.");
		elseif (in_array($type, ["liveupdate_contributor_invite", "liveupdate_contributor"]))
			throw new InvalidArgumentException("\$type parameter must be one of liveupdate_contributor_invite, liveupdate_contributor.");

		$url = sprintf("%s/api/live/{$thread}/invite_contributor", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"name" => $name,
			"permissions" => $permissions,
			"type" => $type,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Leave Contributor Of Live Thread
	 *
	 * Abdicates contributorship of the thread
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_leave_contributor
	 * @param string $thread
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function leaveContributorOfLiveThread($thread) {
		if (!is_string($thread))
			throw new InvalidArgumentException("\$thread parameter in editLiveThread method only accepts string.");

		$url = sprintf("%s/api/live/{$thread}/leave_contributor", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Revoke Live Thread Contributorship
	 *
	 * Revokes another user's contributorship
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_rm_contributor
	 * @param string $thread
	 * @param string $id Fullname of a account
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function revokeLiveThreadContributorship($thread, $id) {
		if (!is_string($thread) || !is_string($id))
			throw new InvalidArgumentException("\$thread & \$id parameters only accepts string.");

		$url = sprintf("%s/api/live/{$thread}/rm_contributor", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
     * Set Live Thread Contributor Permissions
	 *
	 * Changes a contributor or contributor invite's permissions
	 *
	 * @scope livemanage
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_live_{thread}_set_contributor_permissions
	 * @param string $thread
	 * @param string $name Name of an existing user
	 * @param string $permissions Permission description e.g. +update,+edit,-manage
	 * @param string $type One of liveupdate_contributor_invite, liveupdate_contributor
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setLiveThreadContributorPermissions($thread, $name, $permissions, $type) {
		if (!is_string($thread) || !is_string($name) || !is_string($permissions) || !is_string($type))
			throw new InvalidArgumentException("Parameters in setLiveThreadContributorPermissions method only accepts strings.");
		elseif (in_array($type, ["liveupdate_contributor_invite", "liveupdate_contributor"]))
			throw new InvalidArgumentException("\$type parameter must be one of liveupdate_contributor_invite, liveupdate_contributor.");

		$url = sprintf("%s/api/live/{$thread}/set_contributor_permissions", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"name" => $name,
			"permissions" => $permissions,
			"type" => $type,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Banner
	 *
	 * Removes the subreddit's custom mobile banner
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_delete_sr_banner
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteBanner($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("deleteBanner method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/delete_sr_banner", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Header
	 *
	 * Removes the subreddit's custom header image
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_delete_sr_header
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteHeader($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("deleteHeader method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/delete_sr_header", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Icon
	 *
	 * Removes the subreddit's custom mobile icon
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_delete_sr_icon
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteIcon($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("deleteIcon method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/delete_sr_icon", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Image
	 *
	 * Removes an image from the subreddit's custom image set
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_delete_sr_img
	 * @param string $subreddit The subreddit to use
	 * @param string $name A valid subreddit image name
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteImage($subreddit, $name) {
		if (!is_string($subreddit) || !is_string($name))
			throw new InvalidArgumentException("deleteImage method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/delete_sr_img", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"img_name" => $name,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Upload Image
	 *
	 * Adds or replaces a subreddit image, custom header logo, custom mobile icon, or custom mobile banner
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_upload_sr_img
	 * @param string $file Image file path. Allowed formats: jpg & png. Max size 500kb.
	 * @param string $subreddit The subreddit to use
	 * @param bool $logo Determine if image should be used as logo, ignores name if true
	 * @param string $name Image name
	 * @return bool|object cURL Response
	 * @throws Exception|InvalidArgumentException
	 */
	public function uploadImage($file, $subreddit, $logo = false, $name = "") {
		if (!is_string($subreddit) || !is_string($name))
			throw new InvalidArgumentException("\$name and \$subreddit parameters in uploadSubImage method must be strings.");
		elseif (!is_bool($logo))
			throw new InvalidArgumentException("\$logo parameter in uploadSubImage method only accepts boolean.");
		elseif (!is_string($file) || !file_exists($file))
			throw new Exception("$file does not exist.");

		$url = sprintf("%s/r/{$subreddit}/api/upload_sr_img", self::ENDPOINT_OAUTH);
		$ext = pathinfo($file)["extension"];

		if (!in_array($ext, ["jpg", "jpeg", "png"]))
			throw new Exception("Invalid image file format. Allowed formats: jpg, png.");

		$postData = [
			"header" => (int)$logo,
			"name" => $name,
			"img_type" => $ext,
			"file" => new CURLFile($file, "image/$ext")
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Stylesheet
	 *
	 * Updates stylesheet of subreddit
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_subreddit_stylesheet
	 * @param string $subreddit The subreddit to use
	 * @param string $content The new stylesheet content
	 * @param string $reason Description, max 256 characters
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setStylesheet($subreddit, $content, $reason = "") {
		if (!is_string($subreddit) || !is_string($content) || !is_string($reason))
			throw new InvalidArgumentException("setStylesheet method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/subreddit_stylesheet", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"op" => "save",
			"reason" => $reason,
			"stylesheet_contents" => $content,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Stylesheet
	 *
	 * Fetches stylesheet of subreddit
	 *
	 * @scope any (?)
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_subreddit_stylesheet
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getStylesheet($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("getStylesheet method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/about/stylesheet", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Set Subreddit Settings
	 *
	 * Configures a subreddit
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_site_admin
	 * @param string $subreddit The subreddit to use
	 * @param array $opts Settings. For a list of available keys, check @link.
	 * @return bool|object cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setSubSettings($subreddit, array $opts) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter in setSubSettings method only accepts strings.");

		$url = sprintf("%s/api/site_admin", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"name" => $subreddit,
			"captcha" => null, // needed?
			"iden" => null, // needed?
			"suggested_comment_sort" => null, // or "confidence"? needed?
		];

		$oldData = $this->getSubSettings($subreddit)->data;

		$rename = [
			"default_set" => "allow_top",
			"domain_css" => "css_on_cname",
			"title" => "header-title",
			"language" => "lang",
			"content_options" => "link_type",
			"domain_sidebar" => "show_cname_sidebar",
			"subreddit_id" => "sr",
			"subreddit_type" => "type",
		];

		foreach ($rename as $old => $new) {
			$oldData[$new] = $oldData[$old];
			unset($oldData[$old]);
		}

		$remove = [
			"domain",
			"header_hover_text",
		];

		foreach ($remove as $key) {
			unset($oldData[$key]);
		}

		$oldData = array_merge($oldData, $postData);
		$postData = array_merge($oldData, $opts);

		if ($diff = array_diff(array_keys($postData), array_keys($oldData)))
			throw new InvalidArgumentException("Invalid option key(s) provided: " . join(", ", $diff));

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Subreddit Settings
	 *
	 * Fetches the current settings of a subreddit
	 *
	 * @scope modconfig
	 * @link http://www.reddit.com/dev/api/oauth#GET_r_{subreddit}_about_edit
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getSubSettings($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("getSubSettings method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/about/edit", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Mute Message Author
	 *
	 * Mutes user via modmail
	 *
	 * @scope modcontributors
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_mute_message_author
	 * @param string $id The fullname of a thing to return results after
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function muteMessageAuthor($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("muteMessageAuthor method only accepts strings.");

		$url = sprintf("%s/api/mute_message_author", self::ENDPOINT_OAUTH);

		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Unmute Message Author
	 *
	 * Unmutes user via modmail
	 *
	 * @scope modcontributors
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unmute_message_author
	 * @param string $id The fullname of a thing to return results after
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function unmuteMessageAuthor($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("unmuteMessageAuthor method only accepts strings.");

		$url = sprintf("%s/api/unmute_message_author", self::ENDPOINT_OAUTH);

		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Clear Flair Templates
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_clearflairtemplates
	 * @param string $subreddit
	 * @param string $flair_type One of USER_FLAIR, LINK_FLAIR
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function clearFlairTemplates($subreddit, $flair_type) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter in clearFlairTemplates method must be of type string.");
		elseif (!in_array($flair_type, ["USER_FLAIR", "LINK_FLAIR"]))
			throw new InvalidArgumentException("\$flair_type parameter in clearFlairTemplates method must be either USER_FLAIR or LINK_FLAIR.");

		$url = sprintf("%s/r/{$subreddit}/api/clearflairtemplates", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"flair_type" => $flair_type,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Flair
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_deleteflair
	 * @param string $subreddit
	 * @param string $user A user by name
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteFlair($subreddit, $user) {
		if (!is_string($subreddit) || !is_string($user))
			throw new InvalidArgumentException("deleteFlair method only accept strings.");

		$url = sprintf("%s/r/{$subreddit}/api/deleteflair", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"name" => $user,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Delete Flair Template
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_deleteflairtemplate
	 * @param string $subreddit
	 * @param string $flair_template_id
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function deleteFlairTemplate($subreddit, $flair_template_id) {
		if (!is_string($subreddit) || !is_string($flair_template_id))
			throw new InvalidArgumentException("deleteFlairTemplate method only accept strings.");

		$url = sprintf("%s/r/{$subreddit}/api/deleteflairtemplate", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"flair_template_id" => $flair_template_id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set flair
	 *
	 * Sets or clears a user's flair in a subreddit
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flair
	 * @param string $subreddit The subreddit to use
	 * @param string $user The name of the user
	 * @param string $text Flair text to assign
	 * @param string $cssClass CSS class to assign to the flair text
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setFlair($subreddit, $user, $text, $cssClass) {
		if (!is_string($subreddit) || !is_string($user) || !is_string($text) || !is_string($cssClass))
			throw new InvalidArgumentException("setFlair method only accept strings.");

		$url = sprintf("%s/r/{$subreddit}/api/flair", self::ENDPOINT_OAUTH);
		$postData = [
			"name" => $user,
			"text" => $text,
			"css_class" => $cssClass,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Flair Configuration
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flairconfig
	 * @param string $subreddit The subreddit to use
	 * @param bool $flair_enabled
	 * @param string $flair_position Must be either left or right
	 * @param bool $flair_self_assign
	 * @param string $link_flair_position Must be either left or right
	 * @param bool $link_flair_self_assign
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setFlairConfig(
		$subreddit,
		$flair_enabled,
		$flair_position,
		$flair_self_assign,
		$link_flair_position,
		$link_flair_self_assign
	) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter setFlairConfig method must be of type string.");
		elseif (!in_array($link_flair_position, ["left", "right"]) || !in_array($flair_position, ["left", "right"]))
			throw new InvalidArgumentException("\$flair_position parameter in setFlairConfig method must be either left or right.");
		elseif (!is_bool($flair_enabled) || !is_bool($flair_self_assign) || !is_bool($link_flair_self_assign))
			throw new InvalidArgumentException("Unexpected parameter type in setFlairConfig method when expecting boolean.");

		$url = sprintf("%s/r/{$subreddit}/api/flairconfig", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"flair_enabled" => $flair_enabled,
			"flair_position" => $flair_position,
			"flair_self_assign_enabled" => $flair_self_assign,
			"link_flair_position" => $link_flair_position,
			"link_flair_self_assign_enabled" => $link_flair_self_assign,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Flair CSV
	 *
	 * Posts a CSV file of flair settings to a subreddit
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flaircsv
	 * @param string $subreddit The subreddit to use
	 * @param string $flairCSV CSV file contents, up to 100 lines
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setFlairCSV($subreddit, $flairCSV) {
		if (!is_string($subreddit) || !is_string($flairCSV))
			throw new InvalidArgumentException("setFlairCSV method only accept strings.");

		$url = sprintf("%s/r/{$subreddit}/api/flaircsv", self::ENDPOINT_OAUTH);
		$postData = [
			"flair_csv" => $flairCSV,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Flair List
	 *
	 * Downloads the flair assignments of a subreddit
	 *
	 * @scope modflair
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_flairlist
	 * @param string $subreddit The subreddit to use
	 * @param int $limit The maximum number of items to return (max 1000)
	 * @param string $after Return entries starting after this user
	 * @param string $before Return entries starting before this user
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getFlairList($subreddit, $limit = 25, $after = "", $before = "") {
		if (!is_string($subreddit) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("\$subreddit, \$after and \$before parameters in getFlairList method only accept strings.");
		elseif (!is_int($limit))
			throw new InvalidArgumentException("\$limit parameter in getFlairList method must be of type integer.");
		elseif ($limit > 1000)
			throw new InvalidArgumentException("\$limit parameter in getFlairList method must less than 1000");

		$url = sprintf("%s/r/{$subreddit}/api/flairlist?", self::ENDPOINT_OAUTH);
		$postData = [
			"limit" => $limit,
		];

		foreach (["after" => $after, "before" => $before] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Get Moderation Log
	 *
	 * Fetches a list of recent moderation actions
	 *
	 * @scope modlog
	 * @link http://www.reddit.com/dev/api/oauth#GET_about_log
	 * @param string $subreddit The subreddit to use
	 * @param string $type See list of available keys at @link
	 * @param int $limit The maximum number of items to return (max 1000)
	 * @param string $after Return entries starting after this user
	 * @param string $before Return entries starting before this user
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getModLog($subreddit, $type, $limit = 25, $after = "", $before = "") {
		if (!is_string($subreddit) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("\$subreddit, \$after and \$before parameters in getModLog method only accept strings.");
		elseif (!is_int($limit))
			throw new InvalidArgumentException("\$limit parameter in getModLog method must be of type integer.");
		elseif ($limit > 1000)
			throw new InvalidArgumentException("\$limit parameter in getModLog method must less than 1000");

		$url = sprintf("%s/r/{$subreddit}/about/log?", self::ENDPOINT_OAUTH);
		$postData = [
			"limit" => $limit,
			"type" => $type,
		];

		foreach (["after" => $after, "before" => $before] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Set Permissions
	 *
	 * @scope modothers
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_setpermissions
	 * @param string $subreddit The subreddit to use
	 * @param string $name Name of existing user
	 * @param string $permissions
	 * @param string $type
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setPermissions($subreddit, $name, $permissions, $type) {
		if (!is_string($subreddit) || !is_string($name) || !is_string($type))
			throw new InvalidArgumentException("setPermissions method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/setpermissions", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"name" => $name,
			"permissions" => $permissions,
			"type" => $type,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Approve
	 *
	 * Approves a link or comment
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_approve
	 * @param string $id Fullname of a thing
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function Approve($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("Approve method only accepts strings.");

		$url = sprintf("%s/api/approve", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Distinguish
	 *
	 * Distinguishes a thing's author with a sigil
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_distinguish
	 * @param string $id Fullname of a thing
	 * @param string $how One of yes, no, admin, special
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function Distinguish($id, $how) {
		if (!is_string($id))
			throw new InvalidArgumentException("setPermissions method only accepts strings.");
		elseif (!in_array($how, ["yes", "no", "admin", "special"]))
			throw new InvalidArgumentException("\$how parameter in Distinguish method must be one of yes, no, admin, special.");

		$url = sprintf("%s/api/distinguish", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Ignore Reports
	 *
	 * Prevents future reports on a thing from causing notifications
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_ignore_reports
	 * @param string $id Fullname of a thing
	 * @param bool $state Indicates whether ignore or unignore
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function ignoreReports($id, $state) {
		if (!is_string($id))
			throw new InvalidArgumentException("ignoreReports method only accepts strings.");
		elseif (!is_string($state))
			throw new InvalidArgumentException("\$state parameter in ignoreReports method must be of type boolean.");

		$url = sprintf("%s/api/%signore_reports", self::ENDPOINT_OAUTH, $state ? "" : "un");
		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Mark NSFW
	 *
	 * Marks a link NSFW
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_marknsfw
	 * @param string $id Fullname of a thing
	 * @param bool $state Indicates whether marking or unmarking
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function markNSFW($id, $state) {
		if (!is_string($id))
			throw new InvalidArgumentException("\$id parameter in markNSFW method only accepts strings.");
		elseif (!is_string($state))
			throw new InvalidArgumentException("\$state parameter in markNSFW method must be of type boolean.");

		$url = sprintf("%s/api/%smarknsfw", self::ENDPOINT_OAUTH, $state ? "" : "un");
		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Remove
	 *
	 * Removes a link, comment or modmail message
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_remove
	 * @param string $id Fullname of a thing
	 * @param bool $spam
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function remove($id, $spam = false) {
		if (!is_string($id))
			throw new InvalidArgumentException("remove method only accepts strings.");
		elseif (!is_bool($spam))
			throw new InvalidArgumentException("\$spam parameter in remove method must be of type boolean.");

		$url = sprintf("%s/api/remove", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $id,
			"spam" => $spam,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Contest Mode
	 *
	 * Sets or unsets "contest mode" for a link's comments
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_set_contest_mode
	 * @param string $id Fullname of a thing
	 * @param bool $state Indicates whether enabling or disabling contest mode
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setContestMode($id, $state) {
		if (!is_string($id))
			throw new InvalidArgumentException("setContestMode method only accepts strings.");
		elseif (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in setContestMode method must be of type boolean.");

		$url = sprintf("%s/api/set_contest_mode", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
			"state" => $state,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Sticky
	 *
	 * Sets or unsets a Link as the sticky in its subreddit
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_set_subreddit_sticky
	 * @param string $id Fullname of a thing
	 * @param bool $state Indicates whether adding or removing sticky
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setSticky($id, $state) {
		if (!is_string($id))
			throw new InvalidArgumentException("setSticky method only accepts strings.");
		elseif (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in setSticky method must be of type boolean.");

		$url = sprintf("%s/api/set_subreddit_sticky", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
			"state" => $state,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Suggested Sort
	 *
	 * Sets a suggested sort for a link
	 *
	 * @scope modposts
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_set_suggested_sort
	 * @param string $id Fullname of a thing
	 * @param bool $sort Must be one of confidence, top, new, hot, controversial, old, random, qa, blank
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setSuggestedSort($id, $sort) {
		if (!is_string($id))
			throw new InvalidArgumentException("setSuggestedSort method only accepts strings.");
		elseif (!in_array($sort, ["confidence", "top", "new", "hot", "controversial", "old", "random", "qa", "blank"]))
			throw new InvalidArgumentException("Invalid \$sort parameter in setSuggestedSort method.");

		$url = sprintf("%s/api/set_suggested_sort", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
			"sort" => $sort,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Accept moderator invite
	 *
	 * Accepts an invite to moderate the specified subreddit
	 *
	 * @scope modself
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_accept_moderator_invite
	 * @param string $subreddit
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function acceptModeratorInvite($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("acceptModeratorInvite method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/accept_moderator_invite", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Leave Contributor
	 *
	 * Abdicates approved submitter status in a subreddit
	 *
	 * @scope modself
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_leavecontributor
	 * @param string $id Fullname of a thing
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function leaveContributor($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("leaveContributor method only accepts strings.");

		$url = sprintf("%s/api/leavecontributor", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Leave Moderator
	 *
	 * Abdicates moderator status in a subreddit
	 *
	 * @scope modself
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_leavemoderator
	 * @param string $id Fullname of a thing
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function leaveModerator($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("leaveModerator method only accepts strings.");

		$url = sprintf("%s/api/leavemoderator", self::ENDPOINT_OAUTH);
		$postData = [
			"api_type" => "json",
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Wiki Editor
	 *
	 * Allows/denies a user to edit a wiki page
	 *
	 * @scope modwiki
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_wiki_alloweditor_{act}
	 * @param string $username The name of an existing user
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @param string $act The action to perform. Must be either del or add.
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setWikiEditor($username, $subreddit, $page, $act) {
		if (!is_string($username) || !is_string($subreddit) || !is_string($page) || !is_string($act))
			throw new InvalidArgumentException("setWikiEditor method only accepts strings.");
		elseif (!in_array($act, ["del", "add"]))
			throw new InvalidArgumentException("\$act parameter in setWikiEditor method must be one of del, add.");

		$url = sprintf("%s/r/{$subreddit}/api/wiki/alloweditor/{$act}", self::ENDPOINT_OAUTH);
		$postData = [
			"act" => $act,
			"page" => $page,
			"username" => $username,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Hide Wiki Page
	 *
	 * Toggles the public visibility of a wiki page revision
	 *
	 * @scope modwiki
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_wiki_hide
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @param string $revID A wiki revision ID
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function hideWikiPage($subreddit, $page, $revID) {
		if (!is_string($subreddit) || !is_string($page) || !is_string($revID))
			throw new InvalidArgumentException("hideWikiPage method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/wiki/hide", self::ENDPOINT_OAUTH);
		$postData = [
			"page" => $page,
			"revision" => $revID,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Revert Wiki Page
	 *
	 * Toggles the public visibility of a wiki page revision
	 *
	 * @scope modwiki
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_wiki_revert
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @param string $revID A wiki revision ID
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function revertWikiPage($subreddit, $page, $revID) {
		if (!is_string($subreddit) || !is_string($page) || !is_string($revID))
			throw new InvalidArgumentException("revertWikiPage method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/api/wiki/revert", self::ENDPOINT_OAUTH);
		$postData = [
			"page" => $page,
			"revision" => $revID,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Wiki Page Settings
	 *
	 * Retrieves the current permission settings for a wiki page
	 *
	 * @scope modwiki
	 * @link https://www.reddit.com/dev/api/oauth#GET_wiki_settings_{page}
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiPageSettings($subreddit, $page) {
		if (!is_string($subreddit) || !is_string($page))
			throw new InvalidArgumentException("getWikiPageSettings method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/settings/{$page}", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Set Wiki Page Settings
	 *
	 * Updates the permissions and visibility of wiki page
	 *
	 * @scope modwiki
	 * @link https://www.reddit.com/dev/api/oauth#POST_wiki_settings_{page}
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @param integer $permLevel
	 * @param boolean $listed
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setWikiPageSettings($subreddit, $page, $permLevel, $listed) {
		if (!is_string($subreddit) || !is_string($page))
			throw new InvalidArgumentException("\$subreddit & \$page parameters only accepts strings.");
		elseif (!is_int($permLevel))
			throw new InvalidArgumentException("\$permLevel parameter in setWikiPageSettings method must be of type integer.");
		elseif (!is_bool($listed))
			throw new InvalidArgumentException("\$listed parameter in setWikiPageSettings must be of type boolean.");

		$url = sprintf("%s/r/{$subreddit}/wiki/settings/", self::ENDPOINT_OAUTH);
		$postData = [
			"page" => $page,
			"listed" => $listed,
			"permlevel" => $permLevel,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Edit Wiki Page
	 *
	 * Updates a wiki page
	 *
	 * @scope wikiedit
	 * @link https://www.reddit.com/dev/api/oauth#POST_api_wiki_edit
	 * @param string $subreddit The name of an existing subreddit
	 * @param string $page The name of an existing wiki page
	 * @param string $content
	 * @param string $previous The starting point revision for this edit
	 * @param string $reason A string up to 256 characters long, consisting of printable character
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function editWikiPage($subreddit, $page, $content, $previous, $reason) {
		if (!is_string($subreddit) || !is_string($page) || !is_string($content) || !is_string($previous) || !is_string($reason))
			throw new InvalidArgumentException("editWikiPage method only accepts strings.");
		elseif (!strlen($reason) > 256)
			throw new InvalidArgumentException("\$reason parameter in editWikiPage method must not be longer than 256 characters.");

		$url = sprintf("%s/r/{$subreddit}/api/wiki/edit", self::ENDPOINT_OAUTH);
		$postData = [
			"page" => $page,
			"content" => $content,
			"previous" => $previous,
			"reason" => $reason,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Wiki Page
	 *
	 * Gets a specific wiki page from a subreddit
	 *
	 * @scope wikiread
	 * @link http://www.reddit.com/dev/api#GET_wiki_{page}
	 * @param string $subreddit
	 * @param string $page Name of the wiki page
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiPage($subreddit, $page) {
		if (!is_string($subreddit) || !is_string($page))
			throw new InvalidArgumentException("getWikiPage method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/{$page}.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Wiki Pages
	 *
	 * Gets a listing of wiki pages for a subreddit
	 *
	 * @scope wikiread
	 * @link http://www.reddit.com/dev/api#GET_wiki_pages
	 * @param string $subreddit
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiPages($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("getWikiPages method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/pages.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Wiki Page Discussion
	 *
	 * Gets the listing of subreddits wiki page discussions
	 *
	 * @scope wikiread
	 * @link http://www.reddit.com/dev/api#GET_wiki_discussions_{page}
	 * @param string $subreddit
	 * @param string $page Name of the wiki page
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiPageDiscussion($subreddit, $page) {
		if (!is_string($subreddit) || !is_string($page))
			throw new InvalidArgumentException("getWikiPageDiscussion method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/discussions/{$page}.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Wiki Revisions
	 *
	 * Gets a listing of a subreddit"s wiki pages revisions
	 *
	 * @scope wikiread
	 * @link http://www.reddit.com/dev/api#GET_wiki_revisions
	 * @param string $subreddit
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiRevisions($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("getWikiRevisions method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/revisions.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Wiki Page Revisions
	 *
	 * Gets a listing of a specific wiki page"s revisions
	 *
	 * @scope wikiread
	 * @link http://www.reddit.com/dev/api#GET_wiki_revisions_{page}
	 * @param string $subreddit
	 * @param string $page Name of the wiki page
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getWikiPageRevisions($subreddit, $page) {
		if (!is_string($subreddit) || !is_string($page))
			throw new InvalidArgumentException("getWikiPageRevisions method only accepts strings.");

		$url = sprintf("%s/r/{$subreddit}/wiki/revisions/{$page}.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Friend Information
	 *
	 * Gets information about a specified friend
	 *
	 * @scope mysubreddits
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_friends_{username}
	 * @param string $username The username of a friend to search for details on
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getFriendInfo($username) {
		if (!is_string($username))
			throw new InvalidArgumentException("getFriendInfo method only accepts strings.");

		$url = sprintf("%s/api/v1/me/friends/{$username}", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Karma
	 *
	 * Gets breakdown of karma for the current user
	 *
	 * @scope mysubreddits
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_karma
	 * @return object|bool cURL Response
	 */
	public function getKarma() {
		$url = sprintf("%s/api/v1/me/karma", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Subreddit Relationship
	 *
	 * Gets relationship information for subreddits that user belongs to
	 *
	 * @scope mysubreddits
	 * @link http://www.reddit.com/dev/api/oauth#GET_subreddits_mine_{where}
	 * @param string $where The subreddit relationship to search for.  One of
	 *                       subscriber, contributor, or moderator
	 * @param int $limit The number of results to return. Default = 25, Max = 100.
	 * @param string $after The fullname of a thing to return results after
	 * @param string $before The fullname of a thing to return results before
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getSubRel($where = "subscriber", $limit = 25, $after = "", $before = "") {
		if (!is_string($where) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("\$where, \$after and \$before parameters in getSubRel method only accept strings.");
		elseif (!in_array($where, ["subscriber", "contributor", "moderator"]))
			throw new InvalidArgumentException("\$where parameter in getSubRel method must be one of subscriber, contributor, moderator.");
		elseif (!is_int($limit))
			throw new InvalidArgumentException("\$limit parameter in getSubRel method must be of type integer.");
		elseif ($limit > 100)
			throw new InvalidArgumentException("\$limit parameter in getSubRel method must less than 100");

		$url = sprintf("%s/subreddits/mine/{$where}?", self::ENDPOINT_OAUTH);
		$postData = [
			"limit" => $limit,
		];

		foreach (["after" => $after, "before" => $before] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Set Content Block
	 *
	 * Sets a given piece of content to a blocked state via the inbox
	 *
	 * @scope privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_block
	 * @param string $id The full name of the content to block (e.g. t4_ and the message id - t4_1kuinv).
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setContentBlock($id) {
		if (!is_string($id))
			throw new InvalidArgumentException("setContentBlock method only accept strings.");

		$url = sprintf("%s/api/block", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $id,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Send Message
	 *
	 * Sends a message to another user, from the current user
	 *
	 * @scope privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_compose
	 * @param string $to The name of a existing user to send the message to
	 * @param string $subject The subject of the message, no longer than 100 characters
	 * @param string $text The content of the message, in raw markdown
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function sendMessage($to, $subject, $text) {
		if (!is_string($to) || !is_string($subject) || !is_string($text))
			throw new InvalidArgumentException("sendMessage method only accept strings.");

		$url = sprintf("%s/api/compose", self::ENDPOINT_OAUTH);
		$postData = [
			"to" => $to,
			"subject" => $subject,
			"text" => $text
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Set Message State
	 *
	 * Sets the read and unread state of a comma separates list of messages
	 *
	 * @scope privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_read_all_messages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_read_message
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unread_message
	 * @param string $state The state to set the messages to, either read, read_all or unread
	 * @param array $ids A comma separated list of message fullnames (t4_ and the message id - e.g. t4_1kuinv).
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function setMessageState($state = "read", array $ids = null) {
		if (!in_array($state, ["read", "read_all", "unread"]))
			throw new InvalidArgumentException("\$state parameter in setMessageState method must be either read, read_all or unread.");
		elseif ($state != "read_all" && !$ids)
			throw new InvalidArgumentException("\$ids parameter in setMessageState method is either null or empty.");

		$url = sprintf("%s/api/{$state}_message", self::ENDPOINT_OAUTH);
		$postData = [];

		if ($state != "read_all")
			$postData["id"] = join(",", $ids);

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Notifications
	 *
	 * Gets notifications for the current user
	 *
	 * @scope privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_notifications
	 * @param int $count Between 0 and 1000
	 * @param string $sort One of new, old, None
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getNotifications($count = 30, $sort = "new") {
		if (!is_int($count) || $count > 1000 || $count < 0)
			throw new InvalidArgumentException("\$count parameter in getNotifications method must be an integer between 0 and 1000.");
		elseif (!in_array($sort, ["new", "old", "None"]))
			throw new InvalidArgumentException("\$sort parameter in getNotifications method must be either new, old or None.");

		$url = sprintf("%s/api/v1/me/notifications", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get messages
	 *
	 * Gets messages (inbox / unread / sent) for the current user
	 *
	 * @scope privatemessages
	 * @link http://www.reddit.com/dev/api/oauth#GET_message_inbox
	 * @param string $where The message type to return. One of inbox, unread, or sent
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getMessages($where = "inbox") {
		if (!in_array($where, ["inbox", "unread", "sent"]))
			throw new InvalidArgumentException("\$where parameter in getMessages method must be either inbox, unread or sent.");

		$url = sprintf("%s/message/{$where}", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Posts
	 *
	 * Get posts of subreddit which are [see @param $where]
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api/oauth#GET_about_{locations}
	 * @param string $where new|hot|random|top|controversial|reports|spam|modqueue|unmoderated|edited
	 * @param string $subreddit The subreddit to use
	 * @param string $only One of links, comments
	 * @param int $limit The number of results to return (max 100)
	 * @param string $after The fullname of a post which results should be returned after
	 * @param string $before The fullname of a post which results should be returned before
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getPosts($where, $subreddit, $only = "", $limit = 25, $after = "", $before = "") {
		if (!is_string($where) || !is_string($subreddit) || !is_string($only) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("One or more Invalid parameter types in getPosts method.");
		elseif (!in_array($only, ["links", "comments"]))
			throw new InvalidArgumentException("Invalid \$only parameter in getPosts method.");
		elseif (!is_int($limit))
			throw new InvalidArgumentException("\$limit parameter in getPosts method must be of type integer.");
		elseif ($limit > 100)
			throw new InvalidArgumentException("\$limit parameter in getPosts method must be less than 100");

		if (in_array($where, ["new", "hot", "random", "top", "controversial"]))
			$url = sprintf("%s/r/{$subreddit}/{$where}?", self::ENDPOINT_OAUTH);
		else
			$url = sprintf("%s/r/{$subreddit}/about/{$where}?", self::ENDPOINT_OAUTH);

		$postData = [
			"limit" => $limit,
		];

		foreach (["after" => $after, "before" => $before, "only" => $only] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Search
	 *
	 * Searches links page
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api/oauth#GET_subreddits_search
	 * @link http://www.reddit.com/dev/api/oauth#GET_search
	 * @param string $query The query to search for, Max 512 characters.
	 * @param string $subreddit Search a specific subreddit. Pass an empty string to search all.
	 * @param string $sort One of relevance, hot, top, new, comments
	 * @param string $time One of hour, day, week, month, year, all
	 * @param int $count The number of results to return
	 * @param string $after The fullname of a thing to search for results after
	 * @param string $before The fullname of a thing to search for results before
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function search($query, $subreddit = "", $sort = "relevance", $time = "all", $count = 0, $after = "", $before = "") {
		if (!is_int($count))
			throw new InvalidArgumentException("\$count parameter in search method must be of type integer.");
		elseif (strlen($query) > 512)
			throw new InvalidArgumentException("\$query parameter in search method must not be longer than 512 characters.");
		elseif (!is_string($subreddit) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("\$subreddit, \$after & \$before parameters in search method must be of type string.");
		elseif (!in_array($sort, ["relevance", "hot", "top", "new", "comments"]))
			throw new InvalidArgumentException("\$sort parameter must be one of relevance, hot, top, new, comments.");
		elseif (!in_array($time, ["hour", "day", "week", "month", "year", "all"]))
			throw new InvalidArgumentException("\$time parameter must be one of hour, day, week, month, year, all.");

		if ($subreddit)
			$url = sprintf("/subreddits/search?", self::ENDPOINT_OAUTH);
		else
			$url = sprintf("/r/{$subreddit}/search?", self::ENDPOINT_OAUTH);

		$postData = [
			"syntax" => "cloudsearch",
			"sort" => $sort,
			"t" => $time,
		];

		foreach (["after" => $after, "before" => $before, "count" => $count] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Get Sidebar
	 *
	 * Gets the sidebar of a subreddit
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api/oauth#GET_sidebar
	 * @param string $subreddit The subreddit to use
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getSidebar($subreddit) {
		if (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter in getSidebar method must be of type string.");

		$url = sprintf("%s/r/{$subreddit}/sidebar", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get User
	 *
	 * Gets data for specific user
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api#GET_user_{username}_about
	 * @param string $username Name of existing user
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getUser($username) {
		if (!is_string($username))
			throw new InvalidArgumentException("\$username parameter in getUser method must be of type string.");

		$url = sprintf("%s/user/{$username}/about", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Get Users
	 *
	 * Gets users of subreddit who are [see @param $where]
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api/oauth#GET_about_{where}
	 * @param string $where banned|muted|wikibanned|contributors|wikicontributors|moderators
	 * @param string $subreddit The subreddit to use
	 * @param int $limit The number of results to return (max 100)
	 * @param string $after The fullname of a post which results should be returned after
	 * @param string $before The fullname of a post which results should be returned before
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getUsers($where, $subreddit, $limit = 25, $before = "", $after = "") {
		if (!is_string($where) || !is_string($subreddit) || !is_string($after) || !is_string($before))
			throw new InvalidArgumentException("\$where, \$subreddit, \$after and \$before parameters in getUsers method only accept strings.");
		elseif (!in_array($where, ["banned", "muted", "wikibanned", "contributors", "wikicontributors", "moderators"]))
			throw new InvalidArgumentException("\$where parameter must be one of banned, muted, wikibanned, contributors, wikicontributors, moderators.");
		elseif (!is_int($limit))
			throw new InvalidArgumentException("\$limit parameter in getUsers method must be of type integer.");
		elseif ($limit > 100)
			throw new InvalidArgumentException("\$limit parameter in getUsers method must be less than 100");

		$url = sprintf("%s/r/{$subreddit}/about/{$where}?", self::ENDPOINT_OAUTH);
		$postData = [
			"limit" => $limit,
		];

		foreach (["after" => $after, "before" => $before] as $k => $v) {
			if ($v)
				$postData[$k] = $v;
		}

		$url .= http_build_query($postData);

		return self::runCurl($url);
	}

	/**
	 * Get Page Information
	 *
	 * Gets information on a URLs submission on Reddit
	 *
	 * @scope read
	 * @link http://www.reddit.com/dev/api#GET_api_info
	 * @param string $url The URL to get information for
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function getPageInfo($url) {
		if (!is_string($url))
			throw new InvalidArgumentException("\$url parameter in getPageInfo method must be of type string.");

		$url = sprintf("%s/api/info?url=%s", self::ENDPOINT_OAUTH, urlencode($url));

		return self::runCurl($url);
	}

	/**
	 * Hide
	 *
	 * Hides a link
	 *
	 * @scope report
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_hide
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unhide
	 * @param array $ids A list of link fullnames
	 * @param bool $state Determine whether hide or unhide
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function hide(array $ids, $state = true) {
		if (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in hide method must be of type boolean.");
		elseif (empty($ids))
			throw new InvalidArgumentException("\$ids array parameter in hide method must not be empty.");

		$url = sprintf("%s/api/%shide", self::ENDPOINT_OAUTH, $state ? "" : "un");

		$postData = [
			"id" => join(",", $ids),
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Report
	 *
	 * Reports a link, comment or message
	 *
	 * @scope report
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_report
	 * @param string $id Fullname of a thing
	 * @param string $reason Max 100 characters
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function report($id, $reason) {
		if (!is_string($id) || !is_string($reason))
			throw new InvalidArgumentException("\$id & \$reason parameters in report method must be of type string.");
		elseif (strlen($reason) > 100)
			throw new InvalidArgumentException("\$reason parameter in report method must not be longer than 100 characters.");

		$url = sprintf("%s/api/report", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"thing_id" => $id,
			"reason" => $reason,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Save
	 *
	 * Saves a post to your account. Save feeds:
	 * @link http://www.reddit.com/saved/.xml
	 * @link http://www.reddit.com/saved/.json
	 *
	 * @scope save
	 * @link http://www.reddit.com/dev/api#POST_api_save
	 * @link http://www.reddit.com/dev/api#POST_api_unsave
	 * @param string $name the full name of the post to save (name parameter
	 *                     in the getSubscriptions() return value)
	 * @param bool $state Determine whether save or unsave
	 * @param string $category the categorty to save the post to
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function save($name, $state = true, $category = "") {
		if (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in save method must be of type boolean.");
		elseif (!is_string($name) || !is_string($category))
			throw new InvalidArgumentException("\$name & \$category parameters in save method must be of type string.");
		elseif ($state && !$category)
			throw new InvalidArgumentException("\$category parameter in save method must not be empty when \$state is true.");

		$url = sprintf("%s/api/%ssave", self::ENDPOINT_OAUTH, $state ? "" : "un");

		$postData = [
			"id" => $name,
		];

		foreach (["category" => $category] as $k => $v) {
			if ($v && $state)
				$postData[$k] = $v;
		}

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Saved Categories
	 *
	 * Gets a list of categories in which things are currently saved
	 *
	 * @scope save
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_saved_categories
	 * @return object|bool cURL Response
	 */
	public function getSavedCats() {
		$url = sprintf("%s/api/saved_categories", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Create Story
	 *
	 * Creates a new story on a particular subreddit
	 *
	 * @scope submit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_submit
	 * @param string $title The title of the story
	 * @param string $subreddit The subreddit where the story should be added
	 * @param string $type One of link, self
	 * @param string $text Text body if $type is self, else link url
	 * @param bool $send_replies
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function createStory($title, $subreddit, $type, $text, $send_replies = true) {
		if (!is_bool($send_replies))
			throw new InvalidArgumentException("\$state parameter in createStory method must be of type boolean.");
		elseif (!is_string($title) || !is_string($subreddit) || !is_string($type) || !is_string($text))
			throw new InvalidArgumentException("\$title, \$subreddit, \$type & \$text parameters in createStory method must be of type string.");
		elseif (!in_array($type, ["link", "self"]))
			throw new InvalidArgumentException("\$type parameter in createStory method must be one of link, self.");

		$url = sprintf("%s/api/submit", self::ENDPOINT_OAUTH);

		$postData = [
			"api_type" => "json",
			"kind" => $type,
			"title" => urlencode($title),
			"sr" => $subreddit,
			"sendreplies" => $send_replies,
		];

		if ($type == "link")
			$postData["url"] = urlencode($text);
		else
			$postData["text"] = urlencode($text);

		return self::runCurl($url, $postData);
	}

	/**
	 * Subscribe
	 *
	 * Subscribes or unsubscribes from a subreddit
	 *
	 * @scope subscribe
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_subscribe
	 * @param string $subreddit
	 * @param bool $state Determine whether to subscribe or unsubscribe
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function subscribe($subreddit, $state = true) {
		if (!is_bool($state))
			throw new InvalidArgumentException("\$state parameter in subscribe method must be of type boolean.");
		elseif (!is_string($subreddit))
			throw new InvalidArgumentException("\$subreddit parameter in subscribe method must be of type string.");

		$url = sprintf("%s/subscribe", self::ENDPOINT_OAUTH);
		$postData = [
			"sr" => $subreddit,
			"action" => $state ? "sub" : "unsub",
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Vote
	 *
	 * Adds a vote (up / down / neutral) on a story
	 *
	 * @scope vote
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_vote
	 * @param string $name The full name of the post to vote on (name parameter
	 *                     in the getSubscriptions() return value)
	 * @param int $vote The vote to be made (1 = upvote, 0 = no vote, -1 = downvote)
	 * @return object|bool cURL Response
	 * @throws InvalidArgumentException
	 */
	public function vote($name, $vote = 1) {
		if (!is_bool($vote))
			throw new InvalidArgumentException("\$vote parameter in vote method must be of type boolean.");
		elseif (!is_string($name))
			throw new InvalidArgumentException("\$name parameter in vote method must be of type string.");
		elseif (!in_array($name, [-1, 0, 1]))
			throw new InvalidArgumentException("\$name parameter in vote method must be one of -1, 0, 1.");

		$url = sprintf("%s/api/vote", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $name,
			"dir" => $vote,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Get Raw JSON
	 *
	 * Gets Raw JSON for a reddit permalink
	 *
	 * @param string $permalink Permalink to get raw JSON for
	 * @return object|bool cURL Response
	 */
	public function getRawJSON($permalink) {
		if (!is_string($permalink))
			throw new InvalidArgumentException("\$permalink parameter in getRawJSON method must be of type string.");

		$url = sprintf("%s/{$permalink}.json", self::ENDPOINT_OAUTH);

		return self::runCurl($url);
	}

	/**
	 * Set Post Report State
	 *
	 * Hides, unhides, or reports a post on your account
	 *
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_hide
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unhide
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_report
	 * @param string $name The fullname of the post to hide, unhide, or report (name
	 *                parameter in the getSubscriptions() return value)
	 * @param string $state The state to set the post to, either hide, unhide, or report
	 * @return object|bool cURL Response
	 */
	public function setPostReportState($name, $state = "hide") {
		if (!is_string($name) || !is_string($state))
			throw new InvalidArgumentException("\$name & \$state parameters in setPostReportState method must be of type string.");
		elseif (!in_array($state, ["hide", "unhide", "report"]))
			throw new InvalidArgumentException("\$state parameter in vote method must be one of hide, unhide, report.");

		$url = sprintf("%s/api/{$state}", self::ENDPOINT_OAUTH);
		$postData = [
			"id" => $name,
		];

		return self::runCurl($url, $postData);
	}

	/**
	 * Validate Scope
	 *
	 * Checks if scope is valid
	 *
	 * @param string|array $scope
	 * @return bool
	 */
	private function validateScope($scope) {
		if (is_array($scope) && !array_diff($scope, Reddit::$scopes)) {
			return true;
		} elseif (is_string($scope) && in_array($scope, Reddit::$scopes)) {
			return true;
		}

		return false;
	}

	/**
	 * Save Token
	 *
	 * Saves token in a cookie
	 *
	 * @return null
	 */
	private function saveToken() {
		$this->remember = is_numeric($this->remember) ? floor($this->remember) : 3600;

		$cookie_text = join(":", [
			$this->token_type,
			$this->access_token,
			$this->scope,
			$this->authorized_timestamp,
			$this->expire_timestamp,
			$this->refresh_token ?: ""
		]);

		setcookie("reddit_token", $cookie_text, $this->authorized_timestamp + $this->remember, "/");
	}

	/**
	 * Get Token
	 *
	 * Gets token from cookie
	 *
	 * @return bool success, will return false if no cookie is set.
	 */
	private function getToken() {
		if (isset($_COOKIE["reddit_token"])) {
			$token_info = explode(":", $_COOKIE["reddit_token"]);

			$this->token_type = $token_info[0];
			$this->access_token = $token_info[1];
			$this->scope = $token_info[2];
			$this->authorized_timestamp = $token_info[3];
			$this->expire_timestamp = $token_info[4];
			$this->refresh_token = @$token_info[5];

			return true;
		} elseif ($this->access_token) {
			return true;
		}

		return false;
	}

	/**
	 * Revoke Token
	 *
	 * Revokes the token
	 *
	 * @return object|bool cURL Response
	 */
	private function revokeToken() {
		if (isset($_COOKIE["reddit_token"])) {
			unset($_COOKIE["reddit_token"]);
			setcookie("reddit_token", "", time() - 3600);
		}

		$postData = [
			"token" => $this->refresh_token ? $this->refresh_token : $this->access_token,
			"token_type_hint" => $this->refresh_token ? "refresh_token" : "access_token"
		];

		// TODO: this returns a 401 response
		$response = self::runCurl(self::ENDPOINT_OAUTH_REVOKE, $postData);

		unset($this->token_type, $this->access_token, $this->scope, $this->authorized_timestamp,
			$this->expire_timestamp, $this->refresh_token);

		return $response;
	}

	/**
	 * Refresh Token
	 *
	 * Fetches and stores a new token
	 *
	 * @param bool|int $remember Number of seconds to remember user (uses cookies), false if not at all (default).
	 * @return object|bool cURL Response
	 */
	private function refreshToken($remember = false) {
		$this->remember = $remember;

		$postData = [
			"grant_type" => "refresh_token",
			"refresh_token" => $this->refresh_token,
		];

		$token = self::runCurl(self::ENDPOINT_OAUTH_TOKEN, $postData, true);

		if (isset($token->access_token)) {
			$this->access_token = $token->access_token;
			$this->token_type = $token->token_type;
			$this->expire_timestamp = $token->expires_in;
			$this->refresh_token = @$token->refresh_token;

			if ($this->remember !== false) {
				$this->authorized_timestamp = time();
				$this->saveToken();
			}
		}

		return $token;
	}

	/**
	 * Get Transfer Info
	 *
	 * Gets information regarding last curl transfer
	 *
	 * @param string $opt Return specific information
	 * @return mixed cURL transfer information
	 */
	public function getTransferInfo($opt = null) {
		if ($opt)
			return $this->last_transfer_info[$opt];

		return $this->last_transfer_info;
	}

	/**
	 * Run cURL
	 *
	 * Sends cURL request for GET and POST
	 *
	 * @param string $url URL to be requested
	 * @param array $postVals NVP string to be send with POST request
	 * @param bool $auth is it an authentication request
	 * @return bool|object cURL Response
	 * @throws Exception
	 */
	private function runCurl($url, array $postVals = null, $auth = false) {
		$ch = curl_init($url);

		$options = [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_TIMEOUT => 10,
			CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
			CURLOPT_USERPWD => "{$this->client_id}:{$this->client_secret}",
			CURLOPT_SSLVERSION => 4,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_VERBOSE => true,
			CURLOPT_SAFE_UPLOAD => true,
		];

		if (!empty($this->user_agent)) {
			$options[CURLOPT_USERAGENT] = $this->user_agent;
		} elseif (!empty($_SERVER["HTTP_USER_AGENT"])) {
			$options[CURLOPT_USERAGENT] = $_SERVER["HTTP_USER_AGENT"];
		}

		if ($postVals != null) {
			$options[CURLOPT_POST] = true;
			$options[CURLOPT_POSTFIELDS] = $postVals;
		}

		if (!$auth) {
			$options[CURLINFO_HEADER_OUT] = false;
			$options[CURLOPT_HEADER] = false;
			$options[CURLOPT_HTTPHEADER] = ["Authorization: {$this->token_type} {$this->access_token}"];
		}

		curl_setopt_array($ch, $options);
		$apiResponse = curl_exec($ch);
		$response = json_decode($apiResponse);

		//check if non-valid JSON is returned
		if ($error = json_last_error())
			$response = $apiResponse;

		$this->last_transfer_info = curl_getinfo($ch);
		curl_close($ch);

		$http_code = $this->getTransferInfo("http_code");
		if (isset($response->error)) {
			throw new Exception("HTTP response error '$response->error'", $http_code);
		} elseif ($http_code >= 300) {
			throw new Exception("HTTP response status code '$http_code'", $http_code);
		}

		return $response;
	}

}