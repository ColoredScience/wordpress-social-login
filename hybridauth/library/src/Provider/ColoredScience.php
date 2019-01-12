<?php
/*!
* Hybridauth
* https://hybridauth.github.io | https://github.com/hybridauth/hybridauth
*  (c) 2017 Hybridauth authors | https://hybridauth.github.io/license.html
*/

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\UnexpectedApiResponseException;
use Hybridauth\Data;
use Hybridauth\User;

/**
 * Google OAuth2 provider adapter.
 *
 * Example:
 *
 *   $config = [
 *       'callback' => Hybridauth\HttpClient\Util::getCurrentUrl(),
 *       'keys'     => [ 'id' => '', 'secret' => '' ],
 *       'scope'    => 'https://user.coloredscience.com/auth/userinfo.profile',
 *
 *        // google's custom auth url params
 *       'authorize_url_parameters' => [
 *              'approval_prompt' => 'force', // to pass only when you need to acquire a new refresh token.
 *              'access_type'     => ..,      // is set to 'offline' by default
 *              'hd'              => ..,
 *              'state'           => ..,
 *              // etc.
 *       ]
 *   ];
 *
 *   $adapter = new Hybridauth\Provider\Google( $config );
 *
 *   try {
 *       $adapter->authenticate();
 *
 *       $userProfile = $adapter->getUserProfile();
 *       $tokens = $adapter->getAccessToken();
 *       $contacts = $adapter->getUserContacts(['max-results' => 75]);
 *   }
 *   catch( Exception $e ){
 *       echo $e->getMessage() ;
 *   }
 */
class ColoredScience extends OAuth2
{
    /**
    * {@inheritdoc}
    */
    public $scope = 'user-orgs';

    /**
    * {@inheritdoc}
    */
    protected $apiBaseUrl = 'https://user.coloredscience.com/';

    /**
    * {@inheritdoc}
    */
    protected $authorizeUrl = 'https://user.coloredscience.com/oauth/authorize';

    /**
    * {@inheritdoc}
    */
    protected $accessTokenUrl = 'https://user.coloredscience.com/oauth/token';

    /**
    * {@inheritdoc}
    */
    protected $apiDocumentation = 'https://user.coloredscience.com/identity/protocols/OAuth2';

    /**
    * {@inheritdoc}
    */
    protected function initialize()
    {
        parent::initialize();

        $this->AuthorizeUrlParameters += [
            'access_type' => 'offline'
        ];

        $this->tokenRefreshParameters += [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];
    }

    /**
    * {@inheritdoc}
    *
    * See: https://user.coloredscience.com/identity/protocols/OpenIDConnect#obtainuserinfo
    */
    public function getUserProfile()
    {
        $response = $this->apiRequest('api/user');

        $data = new Data\Collection($response);

        if (! $data->exists('id')) {
            throw new UnexpectedApiResponseException('Provider API returned an unexpected response.');
        }

        $userProfile = new User\Profile();

        $userProfile->identifier  = $data->get('sub');
        $userProfile->firstName   = $data->get('fname');
        $userProfile->lastName    = $data->get('lname');
        $userProfile->displayName = $data->get('username');
        $userProfile->photoURL    = $data->get('picture');
        // $userProfile->profileURL  = $data->get('profile');
        // $userProfile->gender      = $data->get('gender');
        // $userProfile->language    = $data->get('locale');
        $userProfile->email       = $data->get('email');

        $userProfile->emailVerified = ($data->get('email_verified') === true || $data->get('email_verified') === 1) ? $userProfile->email : '';

        if ($this->config->get('photo_size')) {
            $userProfile->photoURL .= '?sz=' . $this->config->get('photo_size');
        }

        return $userProfile;
    }

    /**
    * {@inheritdoc}
    */
    public function getUserOrgs($parameters = [])
    {
        $parameters = ['max-results' => 500] + $parameters;

        // Google Gmail and Android contacts
        if (false !== strpos($this->scope, '/m8/feeds/') || false !== strpos($this->scope, '/auth/contacts.readonly')) {
            return $this->getGmailContacts($parameters);
        }
    }
}
