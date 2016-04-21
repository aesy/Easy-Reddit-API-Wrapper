Easy Reddit API Wrapper
=======================
A API Wrapper around the `Reddit OAuth 2 API <http://www.reddit.com/dev/api/oauth>`_ based on Jonathan LeBlancs' `Reddit PHP SDK <https://github.com/jcleblanc/reddit-php-sdk>`_. This project has as of yet not been properly tested. Feel free to try it out, but I would advise against using it in production.

Requires PHP >= 5.4.0

Get Started
-----------
Include/require the Reddit class::

	require("Reddit.class.php");

Create a Reddit instance::

	$reddit = new Reddit($client_id, $client_secret, $redirect_uri);

Or use the App alias::

	$reddit = Reddit::App($client_id, $client_secret, $redirect_uri);

Authenticate by password::

	$reddit->login($username, $password); // no need to worry about scope

Or redirect to Reddit authorization page::

	print_r(Reddit::$scopes); // available scopes
	$reddit->authorize("*", true); // use all scopes & redirect

Make API requests::

    $user = $reddit->getCurrentUser(); // p.s. be sure you have permission/use the correct scope to make the request
    assert($user->comment_karma > PHP_INT_MAX, "Peasant!");

To learn more about the API, read up on `Reddit <https://www.reddit.com/dev/api>`_ and check out the `Reddit class <Reddit.class.php>`_ itself, it is well documented!

Example Code
------------
Easy mode::

	require("Reddit.class.php");

	$reddit = Reddit::App($client_id, $client_secret, $redirect_uri);
    $reddit->authorize("identity", true); // redirect if needed

    // User is authorized!

Or a little more explicit::

	require("Reddit.class.php");

	$reddit = Reddit::App($client_id, $client_secret, $redirect_uri);
	$reddit->authorize("identity", false);

    if ($reddit->isAuthorized()) {
    	// User is authorized!
    } else {
    	$url = $reddit->getAuthURL();
    	header('Location: ' . $url);
    }

To-do List
----------
* Do scope check (?)
* Do proper testing
* Fix issues

Issues
------
* revokeToken request returns a 401 response

License
-------
MIT, see LICENSE file.