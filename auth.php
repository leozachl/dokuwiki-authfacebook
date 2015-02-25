<?php
/**
 * Facebook authentication backend
 * derived from Václav Voborníks FBauth and sentryperm@gmail.coms authgoogle
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Leo Zachl <leo.zachl@gmail.com>
 */

define('DOKU_AUTH', dirname(__FILE__));
// require_once(DOKU_AUTH.'/basic.class.php');
require_once(DOKU_AUTH.'/lib/facebook.php');

// define cookie and session id, append server port when securecookie is configured
if (!defined('AUTHFACEBOOK_COOKIE')) define('AUTHFACEBOOK_COOKIE', 'SPFB'.md5(DOKU_REL.(($conf['securecookie'])?$_SERVER['SERVER_PORT']:'')));

#define('AUTH_USERFILE',DOKU_CONF.'users.auth.php');

class auth_plugin_authfacebook extends auth_plugin_authplain {

  var $users = null;
  var $_pattern = array();

  var $fbsession = array();

  public function __construct() {
    global $conf, $config_cascade;

    parent::__construct();

    $this->cando['external'] = true;
    $this->cando['logout']   = true;
    $this->cando['delUser']   = false;

    $this->success = true;
    return;

  }

  function trustExternal($user,$pass,$sticky=true ){
    global $USERINFO;
    global $conf;
    $sticky ? $sticky = true : $sticky = false; //sanity check

    if (!empty($_SESSION[DOKU_COOKIE]['authfacebook']['info'])) {
      $USERINFO = $_SESSION[DOKU_COOKIE]['authfacebook']['info'];
      if (!$USERINFO['is_facebook']){
        $this->cando['modPass'] = true;
        $this->cando['delUser'] = true;
      }
      $_SERVER['REMOTE_USER'] = $_SESSION[DOKU_COOKIE]['authfacebook']['user'];
      return true;
    }

    //get authplain form login info
    if(!empty($user)){
      if($this->checkPass($user,$pass)){
        $uinfo  = $this->getUserData($user);

        //set user info
        $USERINFO['name'] = $uinfo['name'];
        $USERINFO['mail'] = $uinfo['mail'];
        $USERINFO['grps'] = $uinfo['grps'];
        $USERINFO['is_facebook'] = false;
        $USERINFO['pass'] = ''; // $pass;

        //save data in session
        $_SERVER['REMOTE_USER'] = $uinfo['name'];
        $_SESSION[DOKU_COOKIE]['authfacebook']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['authfacebook']['info'] = $USERINFO;
        trigger_error("plaintextlogin: $user");
        return true;
      } else {
        //invalid credentials - log off
        trigger_error('plaintextlogin: '.$user.' failed');
        msg($this->getLang('badlogin'),-1);
        return false;
      }
    }

    if ($_COOKIE[AUTHFACEBOOK_COOKIE]) {
      $_SESSION[DOKU_COOKIE]['authfacebook']['token'] = $_COOKIE[AUTHFACEBOOK_COOKIE];
    }

    if (($appId = $this->getConf('applicationID')) && ($appSecret = $this->getConf('applicationSecret'))) {
      $facebook = new Facebook(array(
        'appId'      => $appId,
        'secret'     => $appSecret,
        'cookie'     => true,
      ));

      if (isset($_GET['code'])) {
        //get token
        try {
          $fbsession = $facebook->getUser();
          if ($fbsession) {
            //save token in session
            $_SESSION[DOKU_COOKIE]['authfacebook']['token'] = $facebook->getAccessToken();
            //save token in cookies
            $this->_updateCookie($_SESSION[DOKU_COOKIE]['authfacebook']['token'], time() + 60 * 60 * 24 * 365);
            try {
              $me = $facebook->api('/me');
            } catch (FacebookApiException $e) {
              error_log($e);
            }
            if ($me) {
//              $conf['superuser']   = $this->getConf('superuser');
              trigger_error(print_r($me,true));
              $USERINFO['name'] = $me['name'];
              $USERINFO['mail'] = $me['email'];
              $USERINFO['is_facebook'] = true;
              $USERINFO['grps'] = array( $this->getConf('defaultgroup'));
              if (($fbgroupid = $this->getConf('fbgid2group')) != ''){
                if ($fbg2user = json_decode($fbgroupid,TRUE)){
                  $fbgroups = $facebook->api($me['id'].'?fields=groups');
                  foreach($fbgroups['groups']['data'] as $group){
                    if (isset($fbg2user[$group['id']])) $USERINFO['grps'][] = $fbg2user[$group['id']];
                  }
                }
              }
              if (in_array($me['id'],json_decode($this->getConf('superuser'))))
                $USERINFO['grps'][] = 'admin';
              trigger_error($me['username'].'('.$me['id'].') '.print_r($USERINFO['grps'],true));
              $user = $me['id'];
              $_SESSION[DOKU_COOKIE]['authfacebook']['userid'] = $user;
              $_SERVER['REMOTE_USER'] = $user;
              $_SESSION[DOKU_COOKIE]['authfacebook']['user'] = $me['username'];
              $_SESSION[DOKU_COOKIE]['authfacebook']['pass'] = '';
              $_SESSION[DOKU_COOKIE]['authfacebook']['info'] = $USERINFO;

              //redirect to login page
              header("Location: ".wl('start', array(), true, '&'));
              die();

            } //me
          }  // FB session
        } catch (Exception $e) {
          msg('Auth Facebook Error: '.$e->getMessage());
        }
      }

      if (!isset($_SESSION[DOKU_COOKIE]['authfacebook']['auth_url']))
      $_SESSION[DOKU_COOKIE]['authfacebook']['auth_url'] = $facebook->getLoginUrl(
        array(
          'next' => $_SERVER['HTTP_REFERER'],
          'redirect_uri' => wl('start',array('do'=>'login'),true, '&'),
          'canvas'    => 0,
          'fbconnect' => 1,
          'scope' => 'user_groups,read_stream,publish_stream,user_photos,friends_photos'   //for future usage
        )
      );
    }

    return false;
  }

  function logOff(){
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['token']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['user']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['info']);
    unset($_SESSION[DOKU_COOKIE]['authfacebook']['userid']);
    // clear the cookie
    $this->_updateCookie('', time() - 600000);
  }

  function _updateCookie($value, $time) {
    global $conf;

    $cookieDir = empty($conf['cookiedir']) ? DOKU_REL : $conf['cookiedir'];
    if (version_compare(PHP_VERSION, '5.2.0', '>')) {
      setcookie(AUTHFACEBOOK_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()), true);
    } else {
      setcookie(AUTHFACEBOOK_COOKIE, $value, $time, $cookieDir, '', ($conf['securecookie'] && is_ssl()));
    }
  }

}

//Setup VIM: ex: et ts=2 enc=utf-8 :
