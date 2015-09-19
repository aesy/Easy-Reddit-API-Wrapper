<?php

// TODO: refresh token

/**
 * Reddit PHP SDK
 *
 * Provides a SDK for accessing the Reddit APIs
 * Useage:
 *   $redditor = new reddit($client_id, $client_secret)->login($username, $password);
 *   $karma = $redditor->getKarma();
 */
class Reddit {
	private static $ENDPOINT_OAUTH = 'https://oauth.reddit.com';
	private static $ENDPOINT_OAUTH_AUTHORIZE = 'https://ssl.reddit.com/api/v1/authorize';
	private static $ENDPOINT_OAUTH_TOKEN = 'https://ssl.reddit.com/api/v1/access_token';
	private static $ENDPOINT_OAUTH_REDIRECT = 'http://localhost/reddit/test.php';

	private $client_id;
	private $client_secret;
	private $scopes;
	private $access_token;
	private $token_type;
	private $user_agent;

	/**
	 * Class Constructor
	 *
	 * @link https://github.com/reddit/reddit/wiki/
	 * @param string $client_id
	 * @param string $client_secret
	 * @param string $user_agent (optional) eg. "webapp:{APPNAME}:v1.0 (by /u/{USERNAME})"
	 */
	public function __construct($client_id, $client_secret, $user_agent = null) {
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->user_agent = $user_agent ? $user_agent : '';
	}

	/**
	 * @param $username
	 * @param $password
	 * @param bool $remember save token in cookie
	 * @return Reddit or false if authorization fail
	 */
	public function login($username, $password, $remember = true) {
		if ($this->isAuthorized() && $username == $this->getUser())
			return $this;

		$postvals = sprintf("username=%s&password=%s&grant_type=password&client_id=%s",
			$username,
			$password,
			$this->client_id);

		$token = self::runCurl(self::$ENDPOINT_OAUTH_TOKEN, $postvals, true);

		if (isset($token->access_token)) {
			$this->access_token = $token->access_token;
			$this->token_type = $token->token_type;

			if ($remember)
				$this->saveToken();

			return $this;
		}

		return false;
	}

	/**
	 * @param string $scopes
	 * @param bool $redirect redirect to authorization url
	 * @param bool $remember save token in cookie
	 * @param bool $force force new authorization
	 * @return Reddit or false if authorization fail
	 */
	public function authorize($scopes = '*', $redirect = true, $remember = true, $force = false) {
		$this->scopes = $scopes;

		if ($this->isAuthorized() && !$force)
			return $this;

		if (isset($_GET['code'])) {
			$code = $_GET["code"];

			$postvals = sprintf("code=%s&redirect_uri=%s&grant_type=authorization_code&client_id=%s",
				$code,
				self::$ENDPOINT_OAUTH_REDIRECT,
				$this->client_id);

			$token = self::runCurl(self::$ENDPOINT_OAUTH_TOKEN, $postvals, true);

			if (isset($token->access_token)) {
				$this->access_token = $token->access_token;
				$this->token_type = $token->token_type;

				if ($remember)
					$this->saveToken();

				return $this;
			}
		}

		if ($redirect)
			header("Location: {$this->getAuthURL()}");

		return false;
	}

	/**
	 * @return bool is authorized
	 */
	public function isAuthorized() {
		if (isset($_COOKIE['reddit_token'])) {
			$token_info = explode(":", $_COOKIE['reddit_token']);
			$this->token_type = $token_info[0];
			$this->access_token = $token_info[1];

			return true;
		}

		return false;
	}

	/**
	 * @return string authorization url
	 */
	public function getAuthURL() {
		return sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			self::$ENDPOINT_OAUTH_AUTHORIZE,
			$this->client_id,
			self::$ENDPOINT_OAUTH_REDIRECT,
			$this->scopes,
			rand());
	}

	/**
	 * Needs CAPTCHA
	 *
	 * Checks whether CAPTCHAs are needed for API endpoints
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_needs_captcha.json
	 */
	public function getCaptchaReqs() {
		$urlNeedsCaptcha = self::$ENDPOINT_OAUTH . "/api/needs_captcha.json";

		return self::runCurl($urlNeedsCaptcha);
	}

	/**
	 * Get New CAPTCHA
	 *
	 * Gets the iden of a new CAPTCHA, if the user cannot read the current one
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_new_captcha
	 */
	public function getNewCaptcha() {
		$urlNewCaptcha = self::$ENDPOINT_OAUTH . "/api/new_captcha";
		$postData = "api_type=json";

		return self::runCurl($urlNewCaptcha, $postData);
	}

	/**
	 * Get CAPTCHA Image
	 *
	 * Fetches a new CAPTCHA image from a given iden value
	 * @link http://www.reddit.com/dev/api/oauth#GET_captcha_{iden}
	 * @param string $iden The iden value of a new CAPTCHA from getNewCaptcha method
	 */
	public function getCaptchaImg($iden) {
		$urlCaptchaImg = self::$ENDPOINT_OAUTH . "/captcha/$iden";

		return self::runCurl($urlCaptchaImg);
	}

	/**
	 * Create new story
	 *
	 * Creates a new story on a particular subreddit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_submit
	 * @param string $title The title of the story
	 * @param string $link The link that the story should forward to
	 * @param string $subreddit The subreddit where the story should be added
	 */
	public function createStory($title = null, $link = null, $subreddit = null) {
		$urlSubmit = self::$ENDPOINT_OAUTH . "/api/submit";

		//data checks and pre-setup
		if ($title == null || $subreddit == null) {
			return null;
		}
		$kind = ($link == null) ? "self" : "link";

		$postData = sprintf("kind=%s&sr=%s&title=%s&r=%s",
			$kind,
			$subreddit,
			urlencode($title),
			$subreddit);

		//if link was present, add to POST data
		if ($link != null) {
			$postData .= "&url=" . urlencode($link);
		}

		$this->runCurl($urlSubmit, $postData);
	}

	/**
	 * Get user
	 *
	 * Get data for the current user
	 * @link http://www.reddit.com/dev/api#GET_api_v1_me
	 */
	public function getUser() {
		$urlUser = self::$ENDPOINT_OAUTH . "/api/v1/me";

		return self::runCurl($urlUser);
	}

	/**
	 * Get user preferences
	 *
	 * Get preference data for the current user based on fields provided
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_prefs
	 * @param string $fields A comma separated list of pref data to return. Full list at http://www.reddit.com/dev/api/oauth#GET_api_v1_me_prefs.
	 */
	public function getUserPrefs($fields = null) {
		$response = null;

		if ($fields) {
			$urlUserPrefs = self::$ENDPOINT_OAUTH . "/api/v1/me/prefs?fields=$fields";
			$response = self::runCurl($urlUserPrefs);
		}

		return $response;
	}

	/**
	 * Get user trophies
	 *
	 * Get current user trophies
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_trophies
	 */
	public function getUserTrophies() {
		$urlUserTrophies = self::$ENDPOINT_OAUTH . "/api/v1/me/trophies";

		return self::runCurl($urlUserTrophies);
	}

	/**
	 * Get user karma breakdown
	 *
	 * Get breakdown of karma for the current user
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_karma
	 */
	public function getKarma() {
		$urlKarma = self::$ENDPOINT_OAUTH . "/api/v1/me/karma";

		return self::runCurl($urlKarma);
	}

	/**
	 * Get friend information
	 *
	 * Get information about a specified friend
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_v1_me_friends_{username}
	 * @param string $username The username of a friend to search for details on
	 */
	public function getFriendInfo($username) {
		$urlFriendInfo = self::$ENDPOINT_OAUTH . "/api/v1/me/friends/$username";

		return self::runCurl($urlFriendInfo);
	}

	/**
	 * Get user subreddit relationships
	 *
	 * Get relationship information for subreddits that user belongs to
	 * @link http://www.reddit.com/dev/api/oauth#GET_subreddits_mine_{where}
	 * @param string $where The subreddit relationship to search for.  One of
	 *                       subscriber, contributor, or moderator
	 * @param int $limit The number of results to return. Default = 25, Max = 100.
	 * @param string $after The fullname of a thing to return results after
	 * @param string $before The fullname of a thing to return results before
	 */
	public function getSubRel($where = "subscriber", $limit = 25, $after = null, $before = null) {
		$qAfter = (!empty($after)) ? "&after=" . $after : "";
		$qBefore = (!empty($before)) ? "&before=" . $before : "";

		$urlSubRel = sprintf(self::$ENDPOINT_OAUTH . "/subreddits/mine/$where?limit=%s%s%s",
			$where,
			$limit,
			$qAfter,
			$qBefore);

		return self::runCurl($urlSubRel);
	}

	/**
	 * Get messages
	 *
	 * Get messages (inbox / unread / sent) for the current user
	 * @link http://www.reddit.com/dev/api/oauth#GET_message_inbox
	 * @param string $where The message type to return. One of inbox, unread, or sent
	 */
	public function getMessages($where = "inbox") {
		$urlMessages = self::$ENDPOINT_OAUTH . "/message/$where";

		return self::runCurl($urlMessages);
	}

	/**
	 * Send message
	 *
	 * Send a message to another user, from the current user
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_compose
	 * @param string $to The name of a existing user to send the message to
	 * @param string $subject The subject of the message, no longer than 100 characters
	 * @param string $text The content of the message, in raw markdown
	 */
	public function sendMessage($to, $subject, $text) {
		$urlMessages = self::$ENDPOINT_OAUTH . "/api/compose";

		$postData = sprintf("to=%s&subject=%s&text=%s",
			$to,
			$subject,
			$text);

		return self::runCurl($urlMessages, $postData);
	}

	/**
	 * Set read / unread message state
	 *
	 * Sets the read and unread state of a comma separates list of messages
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_read_message
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unread_message
	 * @param string $state The state to set the messages to, either read or unread
	 * @param string $ids A comma separated list of message fullnames (t4_ and the message id - e.g. t4_1kuinv).
	 */
	public function setMessageState($state = "read", $ids) {
		$urlMessageState = self::$ENDPOINT_OAUTH . "/api/{$state}_message";
		$postData = "id=$ids";

		return self::runCurl($urlMessageState, $postData);
	}

	/**
	 * Set content block state
	 *
	 * Sets a given piece of content to a blocked state via the inbox
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_block
	 * @param string $id The full name of the content to block (e.g. t4_ and the message id - t4_1kuinv).
	 */
	public function setContentBlock($id) {
		$urlBlockMessage = self::$ENDPOINT_OAUTH . "/api/block";
		$postData = "id=$id";

		return self::runCurl($urlBlockMessage, $postData);
	}

	/**
	 * Delete link or comment
	 *
	 * Deletes a given link or comment created by the user
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_del
	 * @param string $id The fullname of the link or comment to delete (e.g. t3_1kuinv for link, t1_1kuinv for comment).
	 */
	public function deleteContent($id) {
		$urlDelContent = self::$ENDPOINT_OAUTH . "/api/del";
		$postData = "id=$id";

		return self::runCurl($urlDelContent, $postData);
	}

	/**
	 * Edit comment or self post
	 *
	 * Edits the content of a self post or comment created by the user
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_editusertext
	 * @param string $id The fullname of the link or comment to delete (e.g. t3_1kuinv for link, t1_1kuinv for comment).
	 * @param string $text The raw markdown text to replace the content with.
	 */
	public function editContent($id, $text) {
		$urlEditContent = self::$ENDPOINT_OAUTH . "/api/editusertext";
		$postData = sprintf("thing_id=%s&text=%s&api_type=json",
			$id,
			$text);

		return self::runCurl($urlEditContent, $postData);
	}

	/**
	 * Set Link Reply State
	 *
	 * Enable or disable inbox replies for a link
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_sendreplies
	 * @param string $id The fullname of the link to set the inbox reply state for.
	 * @param bool $state The state to set the link to.  true = enable inbox replies, false = disable inbox replies.
	 */
	public function setReplyState($id, $state) {
		$urlReplyState = self::$ENDPOINT_OAUTH . "/api/sendreplies";
		$postData = "id=$id&state=$state";

		return self::runCurl($urlReplyState, $postData);
	}

	/**
	 * Get user subscriptions
	 *
	 * Get the subscriptions that the user is subscribed to, has contributed to, or is moderator of
	 * @link http://www.reddit.com/dev/api#GET_subreddits_mine_contributor
	 * @param string $where The subscription content to obtain. One of subscriber, contributor, or moderator
	 */
	public function getSubscriptions($where = "subscriber") {
		$urlSubscriptions = self::$ENDPOINT_OAUTH . "/subreddits/mine/$where";

		return self::runCurl($urlSubscriptions);
	}

	/**
	 * Get listing
	 *
	 * Get the listing of submissions from a subreddit
	 * @link http://www.reddit.com/dev/api#GET_listing
	 * @param string $sr The subreddit name. Ex: technology, limit (integer): The number of posts to gather
	 * @param int $limit The number of listings to return
	 */
	public function getListing($sr, $limit = 5) {
		$limit = (isset($limit)) ? "?limit=" . $limit : "";
		if ($sr == 'home' || $sr == 'reddit' || !isset($sr)) {
			$urlListing = self::$ENDPOINT_OAUTH . "/.json{$limit}";
		} else {
			$urlListing = self::$ENDPOINT_OAUTH . "/r/{$sr}/.json{$limit}";
		}

		return self::runCurl($urlListing);
	}

	/**
	 * Get a wiki page
	 *
	 * Gets a specific wiki page from a subreddit
	 * @link http://www.reddit.com/dev/api#GET_wiki_{page}
	 * @param string $sr The subreddit name
	 * @param string $page The name of the wiki page
	 */
	public function getWikiPage($sr, $page) {
		$urlWikiPage = "http://reddit.com/r/{$sr}/wiki/{$page}.json";

		return self::runCurl($urlWikiPage);
	}

	/**
	 * Get a listing of wiki pages
	 *
	 * Gets a listing of wiki pages for a subreddit
	 * @link http://www.reddit.com/dev/api#GET_wiki_pages
	 * @param string $sr The subreddit name
	 */
	public function getWikiPages($sr) {
		$urlWikiPages = "http://reddit.com/r/{$sr}/wiki/pages.json";

		return self::runCurl($urlWikiPages);
	}

	/**
	 * Get a listing of Wiki page discussions
	 *
	 * Gets the listing of subreddits wiki page discussions
	 * @link http://www.reddit.com/dev/api#GET_wiki_discussions_{page}
	 * @param string $sr The subreddit name
	 * @param string $page The name of the wiki page
	 */
	public function getWikiPageDiscussion($sr, $page) {
		$urlWikiPageDiscussions = "http://reddit.com/r/{$sr}/wiki/discussions/{$page}.json";

		return self::runCurl($urlWikiPageDiscussions);
	}

	/**
	 * Get a listing of wiki revisions
	 *
	 * Gets a listing of a subreddit's wiki pages revisions
	 * @link http://www.reddit.com/dev/api#GET_wiki_revisions
	 * @param string $sr The subreddit name
	 */
	public function getWikiRevisions($sr) {
		$urlWikiRevisions = "http://reddit.com/r/{$sr}/wiki/revisions.json";

		return self::runCurl($urlWikiRevisions);
	}

	/**
	 * Get a listing of wiki page revisions
	 *
	 * Gets a listing of a specific wiki page's revisions
	 * @link http://www.reddit.com/dev/api#GET_wiki_revisions_{page}
	 * @param string $sr The subreddit name
	 * @param string $page The name of the wiki page
	 */
	public function getWikiPageRevisions($sr, $page) {
		$urlWikiPageRevisions = "http://reddit.com/r/{$sr}/wiki/revisions/{$page}.json";

		return self::runCurl($urlWikiPageRevisions);
	}

	/**
	 * Search all subreddits
	 *
	 * Get the listing of submissions from a subreddit
	 * @link http://www.reddit.com/dev/api/oauth#GET_subreddits_search
	 * @param string $query The query to search for
	 * @param int $count The number of results to return
	 * @param string $after The fullname of a thing to search for results after
	 * @param string $before The fullname of a thing to search for results before
	 */
	public function search($query, $count = 10, $after = null, $before = null) {
		$qAfter = (!empty($after)) ? "&after=" . $after : "";
		$qBefore = (!empty($before)) ? "&before=" . $before : "";

		$urlSearch = sprintf(self::$ENDPOINT_OAUTH . "/subreddits/search?q=%s&count=%d%s%s",
			$query,
			$count,
			$qAfter,
			$qBefore);

		return self::runCurl($urlSearch);
	}

	/**
	 * Get all subreddits
	 *
	 * Get results for all subreddits combined, sorted by new / popular
	 * @link http://www.reddit.com/dev/api/oauth#GET_subreddits_{where}
	 * @param string $where The fetch method, either new or popular
	 * @param int $limit The number of results to return (max 100)
	 * @param string $after The fullname of a post which results should be returned after
	 * @param string $before The fullname of a post which results should be returned before
	 */
	public function getAllSubs($where = "popular", $limit = 25, $after = null, $before = null) {
		$qAfter = (!empty($after)) ? "&after=" . $after : "";
		$qBefore = (!empty($before)) ? "&before=" . $before : "";

		$urlGetAll = sprintf(self::$ENDPOINT_OAUTH . "/subreddits/%s?limit=%d%s%s",
			$where,
			$limit,
			$qAfter,
			$qBefore);

		return self::runCurl($urlGetAll);
	}

	/**
	 * Get page information
	 *
	 * Get information on a URLs submission on Reddit
	 * @link http://www.reddit.com/dev/api#GET_api_info
	 * @param string $url The URL to get information for
	 */
	public function getPageInfo($url) {
		$response = null;
		if ($url) {
			$urlInfo = self::$ENDPOINT_OAUTH . "/api/info?url=" . urlencode($url);
			$response = self::runCurl($urlInfo);
		}

		return $response;
	}

	/**
	 * Get Subreddit Text
	 *
	 * Get the submission text for a given subreddit
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_submit_text.json
	 * @param string $sr The subreddit to get submission text for
	 */
	public function getSubText($sr = null) {
		$response = null;
		if ($sr) {
			$urlSubText = self::$ENDPOINT_OAUTH . "/r/$sr/api/submit_text.json";
			$response = self::runCurl($urlSubText);
		}

		return $response;
	}

	/**
	 * Get Raw JSON
	 *
	 * Get Raw JSON for a reddit permalink
	 * @param string $permalink permalink to get raw JSON for
	 */
	public function getRawJSON($permalink) {
		$urlListing = self::$ENDPOINT_OAUTH . "/{$permalink}.json";

		return self::runCurl($urlListing);
	}

	/**
	 * Save post
	 *
	 * Save a post to your account.  Save feeds:
	 * http://www.reddit.com/saved/.xml
	 * http://www.reddit.com/saved/.json
	 * @link http://www.reddit.com/dev/api#POST_api_save
	 * @param string $name the full name of the post to save (name parameter
	 *                     in the getSubscriptions() return value)
	 * @param string $category the categorty to save the post to
	 */
	public function savePost($name, $category = null) {
		$response = null;
		$cat = (isset($category)) ? "&category=$category" : "";

		if ($name) {
			$urlSave = self::$ENDPOINT_OAUTH . "/api/save";
			$postData = "id=$name$cat";
			$response = self::runCurl($urlSave, $postData);
		}

		return $response;
	}

	/**
	 * Unsave post
	 *
	 * Unsave a saved post from your account
	 * @link http://www.reddit.com/dev/api#POST_api_unsave
	 * @param string $name the full name of the post to unsave (name parameter
	 *                     in the getSubscriptions() return value)
	 */
	public function unsavePost($name) {
		$response = null;

		if ($name) {
			$urlUnsave = self::$ENDPOINT_OAUTH . "/api/unsave";
			$postData = "id=$name";
			$response = self::runCurl($urlUnsave, $postData);
		}

		return $response;
	}

	/**
	 * Get saved categories
	 *
	 * Get a list of categories in which things are currently saved
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_saved_categories.json
	 */
	public function getSavedCats() {
		$urlSavedCats = self::$ENDPOINT_OAUTH . "/api/saved_categories";

		return self::runCurl($urlSavedCats);
	}

	/**
	 * Get historical user data
	 *
	 * Get the historical data of a user
	 * @link http://www.reddit.com/dev/api/oauth#scope_history
	 * @param string $username the desired user. Must be already authenticated.
	 * @param string $where the data to retrieve. One of overview,submitted,comments,liked,disliked,hidden,saved,gilded
	 */
	public function getHistory($username, $where = "saved") {
		$urlHistory = self::$ENDPOINT_OAUTH . "/user/$username/$where";

		return self::runCurl($urlHistory);
	}

	/**
	 * Set post report state
	 *
	 * Hide, unhide, or report a post on your account
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_hide
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_unhide
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_report
	 * @param string $state The state to set the post to, either hide, unhide, or report
	 * @param string $name The fullname of the post to hide, unhide, or report (name
	 *                parameter in the getSubscriptions() return value)
	 */
	public function setPostReportState($state = "hide", $name) {
		$response = null;
		if ($name) {
			$urlReportState = self::$ENDPOINT_OAUTH . "/api/$state";
			$postData = "id=$name";
			$response = self::runCurl($urlReportState, $postData);
		}

		return $response;
	}

	/**
	 * Add new comment
	 *
	 * Add a new comment to a story
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_comment
	 * @param string $name The full name of the post to comment (name parameter
	 *                     in the getSubscriptions() return value)
	 * @param string $text The comment markup
	 */
	public function addComment($name, $text) {
		$response = null;
		if ($name && $text) {
			$urlComment = self::$ENDPOINT_OAUTH . "/api/comment";
			$postData = sprintf("thing_id=%s&text=%s",
				$name,
				$text);
			$response = self::runCurl($urlComment, $postData);
		}

		return $response;
	}

	/**
	 * Vote on a story
	 *
	 * Adds a vote (up / down / neutral) on a story
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_vote
	 * @param string $name The full name of the post to vote on (name parameter
	 *                     in the getSubscriptions() return value)
	 * @param int $vote The vote to be made (1 = upvote, 0 = no vote,
	 *                  -1 = downvote)
	 */
	public function addVote($name, $vote = 1) {
		$response = null;
		if ($name) {
			$urlVote = self::$ENDPOINT_OAUTH . "/api/vote";
			$postData = sprintf("id=%s&dir=%s", $name, $vote);
			$response = self::runCurl($urlVote, $postData);
		}

		return $response;
	}

	/**
	 * Set flair
	 *
	 * Set or clear a user's flair in a subreddit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flair
	 * @param string $subreddit The subreddit to use
	 * @param string $user The name of the user
	 * @param string $text Flair text to assign
	 * @param string $cssClass CSS class to assign to the flair text
	 */
	public function setFlair($subreddit, $user, $text, $cssClass) {
		$urlFlair = self::$ENDPOINT_OAUTH . "/r/$subreddit/api/flair";
		$postData = sprintf("name=%s&text=%s&css_class=%s",
			$user,
			$text,
			$cssClass);
		$response = self::runCurl($urlFlair, $postData);

		return $response;
	}

	/**
	 * Get flair list
	 *
	 * Download the flair assignments of a subreddit
	 * @link http://www.reddit.com/dev/api/oauth#GET_api_flairlist
	 * @param string $subreddit The subreddit to use
	 * @param int $limit The maximum number of items to return (max 1000)
	 * @param string $after Return entries starting after this user
	 * @param string $before Return entries starting before this user
	 */
	public function getFlairList($subreddit, $limit = 100, $after, $before) {
		$urlFlairList = self::$ENDPOINT_OAUTH . "/r/$subreddit/api/flairlist";
		$postData = sprintf("limit=%s&after=%s&before=%s",
			$limit,
			$after,
			$before);
		$response = self::runCurl($urlFlairList, $postData);

		return $response;
	}

	/**
	 * Set flair CSV file
	 *
	 * Post a CSV file of flair settings to a subreddit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_flaircsv
	 * @param string $subreddit The subreddit to use
	 * @param string $flairCSV CSV file contents, up to 100 lines
	 */
	public function setFlairCSV($subreddit, $flairCSV) {
		$urlFlairCSV = self::$ENDPOINT_OAUTH . "/r/$subreddit/api/flaircsv";
		$postData = "flair_csv=$flairCSV";
		$response = self::runCurl($urlFlairCSV, $postData);

		return $response;
	}

	/**
	 * Get users
	 *
	 * Get users of subreddit who are [see @param $where]
	 * @link http://www.reddit.com/dev/api/oauth#GET_about_{where}
	 * @param string $where banned|muted|wikibanned|contributors|wikicontributors|moderators
	 * @param string $subreddit The subreddit to use
	 * @param int $limit The maximum number of items to return (max 1000)
	 * @param string $after Return entries starting after this user
	 * @param string $before Return entries starting before this user
	 */
	public function getUsers($where, $subreddit, $limit = 100, $after, $before) {
		$urlUsers = self::$ENDPOINT_OAUTH . "/r/$subreddit/about/$where.json";
		$postData = sprintf("limit=%s&after=%s&before=%s",
			$limit,
			$after,
			$before);
		$response = self::runCurl($urlUsers, $postData);

		return $response;
	}

	/**
	 * Update stylesheet
	 *
	 * Update stylesheet of subreddit
	 * @link http://www.reddit.com/dev/api/oauth#POST_api_subreddit_stylesheet
	 * @param string $subreddit The subreddit to use
	 * @param string $content the new stylesheet content
	 * @param string $reason description, max 256 characters
	 */
	public function stylesheet($subreddit, $content, $reason = '') {
		$urlStylesheet = self::$ENDPOINT_OAUTH . "/r/$subreddit/api/subreddit_stylesheet";
		$postData = sprintf("op=save&reason=%s&stylesheet_contents=%s&api_type=json",
			$reason,
			$content);

		$response = self::runCurl($urlStylesheet, $postData);

		return $response;
	}

	/**
	 * Save token in a cookie
	 */
	private function saveToken() {
		$cookie_time = 60 * 59 + time();  // 59 minutes (token expires in 1hr)
		setcookie('reddit_token', "{$this->token_type}:{$this->access_token}", $cookie_time);
	}

	/**
	 * cURL request
	 *
	 * General cURL request function for GET and POST
	 * @link URL
	 * @param string $url URL to be requested
	 * @param string $postVals NVP string to be send with POST request
	 * @param bool $auth is it an authentication request
	 */
	private function runCurl($url, $postVals = null, $auth = false) {
		$ch = curl_init($url);

		$options = [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_TIMEOUT        => 10,
			CURLOPT_HEADER         => false,
			CURLINFO_HEADER_OUT    => false,
			CURLOPT_HTTPHEADER     => ["Authorization: {$this->token_type} {$this->access_token}"],
		];

		if (!empty($this->user_agent)) {
			$options[ CURLOPT_USERAGENT ] = $this->user_agent;
		} elseif (!empty($_SERVER['HTTP_USER_AGENT'])) {
			$options[ CURLOPT_USERAGENT ] = $_SERVER['HTTP_USER_AGENT'];
		}

		if ($postVals != null) {
			$options[ CURLOPT_POSTFIELDS ] = $postVals;
			$options[ CURLOPT_CUSTOMREQUEST ] = "POST";
		}

		if ($auth) {
			$options[ CURLOPT_HTTPAUTH ] = CURLAUTH_BASIC;
			$options[ CURLOPT_USERPWD ] = $this->client_id . ":" . $this->client_secret;
			$options[ CURLOPT_SSLVERSION ] = 4;
			$options[ CURLOPT_SSL_VERIFYPEER ] = false;
			$options[ CURLOPT_SSL_VERIFYHOST ] = 2;
		}

		curl_setopt_array($ch, $options);
		$apiResponse = curl_exec($ch);
		$response = json_decode($apiResponse);

		//check if non-valid JSON is returned
		if ($error = json_last_error())
			$response = $apiResponse;

		curl_close($ch);

		return $response;
	}

}